package api

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// The OpenAPI file is a YAML 1.2 subset: indent maps, "- " sequences,
// flow collections, quoted scalars, and "|" block scalars. It has no comments.
// A module YAML parser is not a dependency this process takes.

type yl struct {
	n      int
	raw    string
	indent int
	text   string
	blank  bool
}

func parseOpenAPI(b []byte) (map[string]any, error) {
	v, err := parseYAML(string(b))
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("openapi: document is not a map")
	}
	return m, nil
}

func parseYAML(s string) (any, error) {
	lines := scanYAML(s)
	v, _, err := parseValue(lines, 0, -1)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("openapi: document is not a map")
	}
	return m, nil
}

func scanYAML(s string) []yl {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	raws := strings.Split(s, "\n")
	out := make([]yl, 0, len(raws))
	for i, raw := range raws {
		if strings.TrimSpace(raw) == "" {
			out = append(out, yl{n: i + 1, blank: true})
			continue
		}
		indent := 0
		for indent < len(raw) && raw[indent] == ' ' {
			indent++
		}
		out = append(out, yl{n: i + 1, raw: raw, indent: indent, text: raw[indent:]})
	}
	return out
}

func parseValue(lines []yl, i, parent int) (any, int, error) {
	for i < len(lines) && lines[i].blank {
		i++
	}
	if i >= len(lines) || lines[i].indent <= parent {
		return nil, i, nil
	}
	if isDash(lines[i].text) {
		return parseSeq(lines, i, lines[i].indent)
	}
	return parseMap(lines, i, lines[i].indent)
}

func parseMap(lines []yl, i, mapIndent int) (any, int, error) {
	m := map[string]any{}
	for {
		for i < len(lines) && lines[i].blank {
			i++
		}
		if i >= len(lines) || lines[i].indent != mapIndent {
			break
		}
		if isDash(lines[i].text) || !isKeyText(lines[i].text) {
			return nil, i, fmt.Errorf("openapi: line %d: expected a key", lines[i].n)
		}
		n, err := fillMapKey(m, lines, i+1, mapIndent, lines[i].text)
		if err != nil {
			return nil, n, err
		}
		i = n
	}
	return m, i, nil
}

func parseSeq(lines []yl, i, dashIndent int) (any, int, error) {
	var items []any
	keyIndent := dashIndent + 2
	for {
		for i < len(lines) && lines[i].blank {
			i++
		}
		if i >= len(lines) || lines[i].indent != dashIndent || !isDash(lines[i].text) {
			break
		}
		rest := dashRest(lines[i].text)
		i++
		if rest == "" {
			val, n, err := parseValue(lines, i, dashIndent)
			if err != nil {
				return nil, n, err
			}
			items = append(items, val)
			i = n
			continue
		}
		if isKeyText(rest) {
			m := map[string]any{}
			n, err := fillMapKey(m, lines, i, keyIndent, rest)
			if err != nil {
				return nil, n, err
			}
			i = n
			for {
				for i < len(lines) && lines[i].blank {
					i++
				}
				if i >= len(lines) || lines[i].indent != keyIndent || isDash(lines[i].text) || !isKeyText(lines[i].text) {
					break
				}
				n, err = fillMapKey(m, lines, i+1, keyIndent, lines[i].text)
				if err != nil {
					return nil, n, err
				}
				i = n
			}
			items = append(items, m)
			continue
		}
		val, err := parseScalarOrFlow(rest)
		if err != nil {
			return nil, i, err
		}
		items = append(items, val)
	}
	if items == nil {
		items = []any{}
	}
	return items, i, nil
}

func fillMapKey(m map[string]any, lines []yl, next, keyIndent int, keyLine string) (int, error) {
	key, inline, kind, err := splitKey(keyLine)
	if err != nil {
		return next, err
	}
	switch kind {
	case kindBlock:
		s, n := readBlock(lines, next, keyIndent)
		m[key] = s
		return n, nil
	case kindInline:
		v, err := parseScalarOrFlow(inline)
		if err != nil {
			return next, err
		}
		m[key] = v
		return next, nil
	default:
		v, n, err := parseValue(lines, next, keyIndent)
		if err != nil {
			return n, err
		}
		m[key] = v
		return n, nil
	}
}

const (
	kindNested = iota
	kindInline
	kindBlock
)

func splitKey(s string) (key, inline string, kind int, err error) {
	if s == "" {
		return "", "", 0, fmt.Errorf("openapi: empty key")
	}
	if s[0] == '"' || s[0] == '\'' {
		q, rest, ok := unquotePrefix(s)
		if !ok {
			return "", "", 0, fmt.Errorf("openapi: bad quoted key %q", s)
		}
		rest = strings.TrimSpace(rest)
		if !strings.HasPrefix(rest, ":") {
			return "", "", 0, fmt.Errorf("openapi: key %q has no colon", q)
		}
		rest = strings.TrimSpace(rest[1:])
		return q, "", classifyRest(rest), nil
	}
	if i := strings.Index(s, ": "); i >= 0 {
		return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+2:]), classifyRest(strings.TrimSpace(s[i+2:])), nil
	}
	trim := strings.TrimRight(s, " ")
	if strings.HasSuffix(trim, ":") {
		return strings.TrimSpace(strings.TrimSuffix(trim, ":")), "", kindNested, nil
	}
	return "", "", 0, fmt.Errorf("openapi: not a key %q", s)
}

func classifyRest(rest string) int {
	switch rest {
	case "", ">", "|", "|-", "|+":
		if rest == "" {
			return kindNested
		}
		if strings.HasPrefix(rest, "|") {
			return kindBlock
		}
		return kindBlock
	default:
		return kindInline
	}
}

func readBlock(lines []yl, i, parent int) (string, int) {
	var b strings.Builder
	base := -1
	for i < len(lines) {
		ln := lines[i]
		if ln.blank {
			if base >= 0 {
				b.WriteByte('\n')
			}
			i++
			continue
		}
		if ln.indent <= parent {
			break
		}
		if base < 0 {
			base = ln.indent
		}
		cut := base
		if cut > len(ln.raw) {
			cut = len(ln.raw)
		}
		b.WriteString(ln.raw[cut:])
		b.WriteByte('\n')
		i++
	}
	s := strings.TrimRight(b.String(), "\n")
	if s != "" {
		s += "\n"
	}
	return s, i
}

func isDash(text string) bool {
	return text == "-" || strings.HasPrefix(text, "- ")
}

func dashRest(text string) string {
	if text == "-" {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(text, "- "))
}

func isKeyText(s string) bool {
	if s == "" {
		return false
	}
	if s[0] == '"' || s[0] == '\'' {
		_, rest, ok := unquotePrefix(s)
		return ok && strings.HasPrefix(strings.TrimSpace(rest), ":")
	}
	if strings.Contains(s, ": ") {
		return true
	}
	return strings.HasSuffix(strings.TrimRight(s, " "), ":")
}

func parseScalarOrFlow(s string) (any, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if s[0] == '[' || s[0] == '{' {
		return parseFlow(s)
	}
	if s[0] == '"' || s[0] == '\'' {
		q, rest, ok := unquotePrefix(s)
		if !ok || strings.TrimSpace(rest) != "" {
			return nil, fmt.Errorf("openapi: bad scalar %q", s)
		}
		return q, nil
	}
	return classifyPlain(s), nil
}

func unquotePrefix(s string) (string, string, bool) {
	if s == "" || (s[0] != '"' && s[0] != '\'') {
		return "", s, false
	}
	q := s[0]
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		c := s[i]
		if c == q {
			if q == '\'' && i+1 < len(s) && s[i+1] == '\'' {
				b.WriteByte('\'')
				i++
				continue
			}
			return b.String(), s[i+1:], true
		}
		if q == '"' && c == '\\' && i+1 < len(s) {
			i++
			switch s[i] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			default:
				b.WriteByte(s[i])
			}
			continue
		}
		b.WriteByte(c)
	}
	return "", "", false
}

func classifyPlain(s string) any {
	switch s {
	case "true":
		return true
	case "false":
		return false
	case "null", "~":
		return nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil && !strings.ContainsAny(s, ".eE") {
		return n
	}
	if strings.Count(s, ".") == 1 {
		if _, err := strconv.ParseFloat(s, 64); err == nil && isPlainFloat(s) {
			return mustFloat(s)
		}
	}
	return s
}

func isPlainFloat(s string) bool {
	if s == "" {
		return false
	}
	dot := false
	for i, c := range s {
		if c == '-' && i == 0 {
			continue
		}
		if c == '.' {
			if dot {
				return false
			}
			dot = true
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
	}
	return dot
}

func mustFloat(s string) float64 {
	n, _ := strconv.ParseFloat(s, 64)
	return n
}

type fp struct {
	s   string
	i   int
	err error
}

func parseFlow(s string) (any, error) {
	p := &fp{s: s}
	v := p.val()
	p.skip()
	if p.err != nil {
		return nil, p.err
	}
	if p.i != len(p.s) {
		return nil, fmt.Errorf("openapi: trailing flow %q", p.s[p.i:])
	}
	return v, nil
}

func (p *fp) peek() byte {
	if p.i >= len(p.s) {
		return 0
	}
	return p.s[p.i]
}

func (p *fp) skip() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t') {
		p.i++
	}
}

func (p *fp) val() any {
	if p.err != nil {
		return nil
	}
	p.skip()
	switch p.peek() {
	case '[':
		return p.seq()
	case '{':
		return p.mapping()
	case '"', '\'':
		return p.quoted()
	case 0:
		p.err = fmt.Errorf("openapi: empty flow")
		return nil
	default:
		return p.plain()
	}
}

func (p *fp) seq() any {
	p.i++
	var items []any
	for {
		p.skip()
		if p.peek() == ']' {
			p.i++
			break
		}
		if p.i >= len(p.s) {
			p.err = fmt.Errorf("openapi: unclosed [")
			break
		}
		items = append(items, p.val())
		if p.err != nil {
			break
		}
		p.skip()
		if p.peek() == ',' {
			p.i++
			continue
		}
		if p.peek() == ']' {
			p.i++
			break
		}
		p.err = fmt.Errorf("openapi: flow sequence at %q", p.s[p.i:])
		break
	}
	if items == nil {
		items = []any{}
	}
	return items
}

func (p *fp) mapping() any {
	p.i++
	m := map[string]any{}
	for {
		p.skip()
		if p.peek() == '}' {
			p.i++
			break
		}
		if p.i >= len(p.s) {
			p.err = fmt.Errorf("openapi: unclosed {")
			break
		}
		var key string
		if p.peek() == '"' || p.peek() == '\'' {
			key = p.quoted()
		} else {
			start := p.i
			for p.i < len(p.s) && p.s[p.i] != ':' {
				p.i++
			}
			key = strings.TrimSpace(p.s[start:p.i])
		}
		p.skip()
		if p.peek() != ':' {
			p.err = fmt.Errorf("openapi: flow map key %q", key)
			break
		}
		p.i++
		m[key] = p.val()
		if p.err != nil {
			break
		}
		p.skip()
		if p.peek() == ',' {
			p.i++
			continue
		}
		if p.peek() == '}' {
			p.i++
			break
		}
		p.err = fmt.Errorf("openapi: flow map at %q", p.s[p.i:])
		break
	}
	return m
}

func (p *fp) quoted() string {
	q := p.s[p.i]
	p.i++
	var b strings.Builder
	for p.i < len(p.s) {
		c := p.s[p.i]
		p.i++
		if c == q {
			if q == '\'' && p.peek() == '\'' {
				p.i++
				b.WriteByte('\'')
				continue
			}
			return b.String()
		}
		if q == '"' && c == '\\' && p.i < len(p.s) {
			e := p.s[p.i]
			p.i++
			switch e {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			default:
				b.WriteByte(e)
			}
			continue
		}
		b.WriteByte(c)
	}
	p.err = fmt.Errorf("openapi: unclosed quote")
	return b.String()
}

func (p *fp) plain() any {
	start := p.i
	for p.i < len(p.s) {
		c := p.s[p.i]
		if c == ',' || c == ']' || c == '}' {
			break
		}
		p.i++
	}
	return classifyPlain(strings.TrimSpace(p.s[start:p.i]))
}

// rewriteSpec points data paths and the server URL at prefix.
// issuer, when it is an absolute origin, replaces the server host.
// An empty issuer leaves the host from the document.
// /oauth/authorize, /oauth/token, and /openapi.json stay at the site root.
func rewriteSpec(doc map[string]any, prefix, issuer string) error {
	paths, ok := doc["paths"].(map[string]any)
	if !ok {
		return fmt.Errorf("openapi: paths")
	}
	next := make(map[string]any, len(paths))
	for k, v := range paths {
		nk := k
		if k == "/api/v1" || strings.HasPrefix(k, "/api/v1/") {
			nk = prefix + strings.TrimPrefix(k, "/api/v1")
		}
		next[nk] = v
	}
	doc["paths"] = next
	servers, ok := doc["servers"].([]any)
	if !ok {
		return fmt.Errorf("openapi: servers")
	}
	for _, item := range servers {
		m, ok := item.(map[string]any)
		if !ok {
			return fmt.Errorf("openapi: server")
		}
		raw, _ := m["url"].(string)
		m["url"] = joinServerURL(raw, prefix, issuer)
	}
	return nil
}

func joinServerURL(raw, prefix, issuer string) string {
	if iu, err := url.Parse(issuer); err == nil && iu.Scheme != "" && iu.Host != "" {
		iu.Path = prefix
		iu.RawQuery = ""
		iu.Fragment = ""
		iu.User = nil
		return iu.String()
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return strings.TrimRight(raw, "/") + prefix
	}
	u.Path = prefix
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}
