package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/majestrate/vibecollector/internal/netdb"
)

func TestClientNetAPI(t *testing.T) {
	s, db := newAPI(t, "/api/v1", "s3cret")
	if _, err := db.PutOAuthClient(context.Background(), "client-a", "secret-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.PutOAuthClient(context.Background(), "client-b", "secret-b"); err != nil {
		t.Fatal(err)
	}
	tokA := tokenFor(t, s, "client-a", "secret-a")
	tokB := tokenFor(t, s, "client-b", "secret-b")
	authA := map[string]string{"Authorization": "Bearer " + tokA}
	authB := map[string]string{"Authorization": "Bearer " + tokB}

	rr := call(s, http.MethodGet, s.prefix+"/protocols", nil, nil)
	if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "unauthorized") {
		t.Fatal(rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Cache-Control") != "no-store" || rr.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatal(rr.Header())
	}

	rr = call(s, http.MethodGet, s.prefix+"/protocols", nil, authA)
	if rr.Code != http.StatusOK || rr.Body.String() != `{"protocols":[]}` {
		t.Fatal(rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(rr.Header().Get("Cache-Control"))
	}

	rr = call(s, http.MethodPost, s.prefix+"/protocols", strings.NewReader(`{"name":"vc-extra","number":254,"aliases":["VX"],"path":"/etc/protocols"}`), authA)
	if rr.Code != http.StatusBadRequest {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = call(s, http.MethodPost, s.prefix+"/protocols", strings.NewReader(`{"name":"../etc/passwd","number":254}`), authA)
	if rr.Code != http.StatusBadRequest {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = call(s, http.MethodPost, s.prefix+"/protocols", strings.NewReader(`{"name":"vc-extra","aliases":["VX"]}`), authA)
	if rr.Code != http.StatusBadRequest {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = call(s, http.MethodPost, s.prefix+"/protocols", strings.NewReader(`{"name":"vc-extra","number":254,"aliases":["VX"]}{"name":"more"}`), authA)
	if rr.Code != http.StatusBadRequest {
		t.Fatal(rr.Code, rr.Body.String())
	}
	if listed, err := db.ListClientProtocols(context.Background(), "client-a"); err != nil || len(listed) != 0 {
		t.Fatal(listed, err)
	}

	rr = call(s, http.MethodPost, s.prefix+"/protocols", strings.NewReader(`{"name":"vc-extra","number":254,"aliases":["VX"]}`), authA)
	if rr.Code != http.StatusCreated {
		t.Fatal(rr.Code, rr.Body.String())
	}
	created := mustJSON(t, rr.Body.Bytes())
	if created["name"] != "vc-extra" || created["number"] != float64(254) {
		t.Fatal(created)
	}
	rr = call(s, http.MethodPost, s.prefix+"/protocols", strings.NewReader(`{"name":"vc-extra","number":253}`), authA)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "exists") {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = call(s, http.MethodPost, s.prefix+"/protocols", strings.NewReader(`{"name":"vc-extra","number":253}`), authB)
	if rr.Code != http.StatusCreated {
		t.Fatal(rr.Code, rr.Body.String())
	}

	rr = call(s, http.MethodGet, s.prefix+"/protocols/vc-extra", nil, authA)
	got := mustJSON(t, rr.Body.Bytes())
	if rr.Code != http.StatusOK || got["number"] != float64(254) {
		t.Fatal(rr.Code, got)
	}
	rr = call(s, http.MethodGet, s.prefix+"/protocols/vc-extra", nil, authB)
	if rr.Code != http.StatusOK || mustJSON(t, rr.Body.Bytes())["number"] != float64(253) {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = call(s, http.MethodGet, s.prefix+"/protocols/missing", nil, authA)
	if rr.Code != http.StatusNotFound {
		t.Fatal(rr.Code, rr.Body.String())
	}

	rr = call(s, http.MethodPut, s.prefix+"/protocols/vc-extra", strings.NewReader(`{"number":252,"aliases":["V2"],"path":"etc/protocols"}`), authA)
	if rr.Code != http.StatusBadRequest {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = call(s, http.MethodPut, s.prefix+"/protocols/vc-extra", strings.NewReader(`{"number":252,"aliases":["V2"]}`), authA)
	if rr.Code != http.StatusOK || mustJSON(t, rr.Body.Bytes())["number"] != float64(252) {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = call(s, http.MethodPut, s.prefix+"/protocols/missing", strings.NewReader(`{"number":1}`), authA)
	if rr.Code != http.StatusNotFound {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = call(s, http.MethodGet, s.prefix+"/protocols", nil, authB)
	list := mustJSON(t, rr.Body.Bytes())
	rows, _ := list["protocols"].([]any)
	if len(rows) != 1 || rows[0].(map[string]any)["number"] != float64(253) {
		t.Fatal(list)
	}

	rr = call(s, http.MethodPost, s.prefix+"/services", strings.NewReader(`{"name":"vc-extra","port":59999,"protocol":"udp","aliases":["vc-echo"],"path":"/etc/services"}`), authA)
	if rr.Code != http.StatusBadRequest {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = call(s, http.MethodPost, s.prefix+"/services", strings.NewReader(`{"name":"vc-extra","protocol":"udp"}`), authA)
	if rr.Code != http.StatusBadRequest {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = call(s, http.MethodPost, s.prefix+"/services", strings.NewReader(`{"name":"vc-extra","port":59999,"protocol":"../udp"}`), authA)
	if rr.Code != http.StatusBadRequest {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = call(s, http.MethodPost, s.prefix+"/services", strings.NewReader(`{"name":"vc-extra","port":59999,"protocol":"udp","aliases":["vc-echo"]}`), authA)
	if rr.Code != http.StatusCreated {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = call(s, http.MethodPost, s.prefix+"/services", strings.NewReader(`{"name":"vc-extra","port":9,"protocol":"tcp"}`), authA)
	if rr.Code != http.StatusCreated {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = call(s, http.MethodPost, s.prefix+"/services", strings.NewReader(`{"name":"vc-extra","port":59999,"protocol":"udp"}`), authA)
	if rr.Code != http.StatusConflict {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = call(s, http.MethodGet, s.prefix+"/services/vc-extra/udp", nil, authB)
	if rr.Code != http.StatusNotFound {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = call(s, http.MethodGet, s.prefix+"/services/vc-extra/udp", nil, authA)
	if rr.Code != http.StatusOK || mustJSON(t, rr.Body.Bytes())["port"] != float64(59999) {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = call(s, http.MethodPut, s.prefix+"/services/vc-extra/udp", strings.NewReader(`{"port":59998,"aliases":[]}`), authA)
	if rr.Code != http.StatusOK || mustJSON(t, rr.Body.Bytes())["port"] != float64(59998) {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = call(s, http.MethodGet, s.prefix+"/services", nil, authA)
	svcList := mustJSON(t, rr.Body.Bytes())["services"].([]any)
	if len(svcList) != 2 {
		t.Fatal(svcList)
	}
	rr = call(s, http.MethodDelete, s.prefix+"/services/vc-extra/tcp", nil, authA)
	if rr.Code != http.StatusNoContent || rr.Body.Len() != 0 {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = call(s, http.MethodDelete, s.prefix+"/services/vc-extra/tcp", nil, authA)
	if rr.Code != http.StatusNotFound {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = call(s, http.MethodDelete, s.prefix+"/protocols/vc-extra", nil, authB)
	if rr.Code != http.StatusNoContent {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = call(s, http.MethodGet, s.prefix+"/protocols/vc-extra", nil, authA)
	if rr.Code != http.StatusOK {
		t.Fatal(rr.Code, rr.Body.String())
	}

	public, _ := newAPI(t, "/api/v1", "")
	pubTok := pkceToken(t, public)
	rr = call(public, http.MethodPost, public.prefix+"/protocols", strings.NewReader(`{"name":"vc-extra","number":254}`), map[string]string{"Authorization": "Bearer " + pubTok})
	if rr.Code != http.StatusBadRequest {
		t.Fatal(rr.Code, rr.Body.String())
	}
}

func TestClientNetLookup(t *testing.T) {
	sys, err := netdb.LoadSystem()
	if err != nil {
		t.Skip(err)
	}
	s, db := newAPI(t, "/api/v1", "s3cret")
	if _, err := db.PutOAuthClient(context.Background(), "client-a", "secret-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.PutOAuthClient(context.Background(), "client-b", "secret-b"); err != nil {
		t.Fatal(err)
	}
	authA := map[string]string{"Authorization": "Bearer " + tokenFor(t, s, "client-a", "secret-a")}
	authB := map[string]string{"Authorization": "Bearer " + tokenFor(t, s, "client-b", "secret-b")}

	number, err := freeProtocol(sys)
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"name":"vc-extra","number":%d,"aliases":["VX"]}`, number)
	rr := call(s, http.MethodPost, s.prefix+"/protocols", strings.NewReader(body), authA)
	if rr.Code != http.StatusCreated {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = call(s, http.MethodGet, s.prefix+"/protocol?name=vc-extra", nil, authA)
	got := mustJSON(t, rr.Body.Bytes())
	if rr.Code != http.StatusOK || got["number"] != float64(number) || got["name"] != "vc-extra" {
		t.Fatal(rr.Code, got)
	}
	rr = call(s, http.MethodGet, s.prefix+"/protocol?name=vc-extra", nil, authB)
	if rr.Code != http.StatusNotFound {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = call(s, http.MethodGet, s.prefix+"/protocol?number="+fmt.Sprint(number), nil, authA)
	if rr.Code != http.StatusOK || mustJSON(t, rr.Body.Bytes())["name"] != "vc-extra" {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = call(s, http.MethodGet, s.prefix+"/protocol?name=vc-extra&number=254", nil, authA)
	if rr.Code != http.StatusBadRequest {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = call(s, http.MethodGet, s.prefix+"/protocol", nil, authA)
	if rr.Code != http.StatusBadRequest {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = call(s, http.MethodGet, s.prefix+"/protocol?number=nope", nil, authA)
	if rr.Code != http.StatusBadRequest {
		t.Fatal(rr.Code, rr.Body.String())
	}

	tcp, err := sys.ProtocolByName("tcp")
	if err != nil {
		t.Fatal(err)
	}
	rr = call(s, http.MethodPost, s.prefix+"/protocols", strings.NewReader(`{"name":"tcp","number":254,"aliases":["NOTTCP"]}`), authA)
	if rr.Code != http.StatusCreated {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = call(s, http.MethodGet, s.prefix+"/protocol?name=tcp", nil, authA)
	got = mustJSON(t, rr.Body.Bytes())
	if rr.Code != http.StatusOK || got["number"] != float64(tcp.Number) || got["name"] != tcp.Name {
		t.Fatal(rr.Code, got, tcp)
	}
	rr = call(s, http.MethodGet, s.prefix+"/protocols/tcp", nil, authA)
	if rr.Code != http.StatusOK || mustJSON(t, rr.Body.Bytes())["number"] != float64(254) {
		t.Fatal(rr.Code, rr.Body.String())
	}

	port, err := freeServicePort(sys)
	if err != nil {
		t.Fatal(err)
	}
	rr = call(s, http.MethodPost, s.prefix+"/services", strings.NewReader(fmt.Sprintf(`{"name":"vc-extra","port":%d,"protocol":"udp","aliases":["vc-echo"]}`, port)), authA)
	if rr.Code != http.StatusCreated {
		t.Fatal(rr.Code, rr.Body.String())
	}
	q := url.Values{}
	q.Set("name", "vc-extra")
	q.Set("protocol", "udp")
	rr = call(s, http.MethodGet, s.prefix+"/service?"+q.Encode(), nil, authA)
	got = mustJSON(t, rr.Body.Bytes())
	if rr.Code != http.StatusOK || got["port"] != float64(port) {
		t.Fatal(rr.Code, got)
	}
	rr = call(s, http.MethodGet, s.prefix+"/service?"+q.Encode(), nil, authB)
	if rr.Code != http.StatusNotFound {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = call(s, http.MethodGet, s.prefix+"/service?port="+fmt.Sprint(port)+"&protocol=udp", nil, authA)
	if rr.Code != http.StatusOK || mustJSON(t, rr.Body.Bytes())["name"] != "vc-extra" {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = call(s, http.MethodGet, s.prefix+"/service?name=vc-extra&port="+fmt.Sprint(port), nil, authA)
	if rr.Code != http.StatusBadRequest {
		t.Fatal(rr.Code, rr.Body.String())
	}
	if host, err := sys.ServiceByName("http", "tcp"); err == nil {
		rr = call(s, http.MethodPost, s.prefix+"/services", strings.NewReader(`{"name":"http","port":1,"protocol":"tcp"}`), authA)
		if rr.Code != http.StatusCreated {
			t.Fatal(rr.Code, rr.Body.String())
		}
		rr = call(s, http.MethodGet, s.prefix+"/service?name=http&protocol=tcp", nil, authA)
		got = mustJSON(t, rr.Body.Bytes())
		if rr.Code != http.StatusOK || got["port"] != float64(host.Port) {
			t.Fatal(rr.Code, got, host.Port)
		}
	}
}

func freeProtocol(sys *netdb.DB) (int, error) {
	for n := 255; n >= 200; n-- {
		if _, err := sys.ProtocolByNumber(n); errors.Is(err, netdb.ErrNotFound) {
			return n, nil
		}
	}
	return 0, errors.New("no free protocol number")
}

func freeServicePort(sys *netdb.DB) (int, error) {
	for port := 59999; port >= 59000; port-- {
		if _, err := sys.ServiceByPort(port, ""); errors.Is(err, netdb.ErrNotFound) {
			return port, nil
		}
	}
	return 0, errors.New("no free service port")
}

func TestClientNetPrefix(t *testing.T) {
	s, db := newAPI(t, "/collector/v1", "s3cret")
	if _, err := db.PutOAuthClient(context.Background(), "client-a", "secret-a"); err != nil {
		t.Fatal(err)
	}
	auth := map[string]string{"Authorization": "Bearer " + tokenFor(t, s, "client-a", "secret-a")}
	rr := call(s, http.MethodGet, "/api/v1/protocols", nil, auth)
	if rr.Code != http.StatusNotFound {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = call(s, http.MethodPost, "/collector/v1/protocols", strings.NewReader(`{"name":"vc-extra","number":254}`), auth)
	if rr.Code != http.StatusCreated {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = call(s, http.MethodGet, "/collector/v1/protocol?name=vc-extra", nil, auth)
	if rr.Code != http.StatusOK {
		t.Fatal(rr.Code, rr.Body.String())
	}
}

func TestOpenAPINetPaths(t *testing.T) {
	s, _ := newAPI(t, "/api/v1", "s3cret")
	doc := mustJSON(t, call(s, http.MethodGet, "/openapi.json", nil, nil).Body.Bytes())
	paths := doc["paths"].(map[string]any)
	for _, p := range []string{
		"/api/v1/protocols",
		"/api/v1/protocols/{name}",
		"/api/v1/protocol",
		"/api/v1/services",
		"/api/v1/services/{name}/{transport}",
		"/api/v1/service",
	} {
		assertOAuth(t, paths, p)
	}
	item := paths["/api/v1/protocols"].(map[string]any)
	if _, ok := item["post"]; !ok {
		t.Fatal("protocols post")
	}
	one := paths["/api/v1/protocols/{name}"].(map[string]any)
	if _, ok := one["put"]; !ok {
		t.Fatal("protocols put")
	}
	if _, ok := one["delete"]; !ok {
		t.Fatal("protocols delete")
	}

	alt, _ := newAPI(t, "/collector/v1", "s3cret")
	doc = mustJSON(t, call(alt, http.MethodGet, "/openapi.json", nil, nil).Body.Bytes())
	paths = doc["paths"].(map[string]any)
	if _, ok := paths["/api/v1/protocols"]; ok {
		t.Fatal("default prefix still listed")
	}
	if _, ok := paths["/collector/v1/protocols/{name}"]; !ok {
		t.Fatal("prefix rewrite dropped protocols")
	}
	if _, ok := paths["/collector/v1/services/{name}/{transport}"]; !ok {
		t.Fatal("prefix rewrite dropped services")
	}
}

func tokenFor(t *testing.T, s *Server, id, secret string) string {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", id)
	form.Set("client_secret", secret)
	form.Set("scope", "read")
	rr := call(s, http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
	if rr.Code != http.StatusOK {
		t.Fatal(rr.Code, rr.Body.String())
	}
	return tokenOf(t, rr.Body.Bytes())
}
