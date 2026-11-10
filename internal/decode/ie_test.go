package decode_test

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

// Lines copied from the IANA IPFIX Information Elements registry.
// https://www.iana.org/assignments/ipfix/ipfix.xhtml
func TestIECommentNames(t *testing.T) {
	src, err := os.ReadFile("ie.go")
	if err != nil {
		t.Fatal(err)
	}
	names := []struct {
		id   int
		name string
	}{
		{1, "octetDeltaCount"},
		{2, "packetDeltaCount"},
		{21, "flowEndSysUpTime"},
		{22, "flowStartSysUpTime"},
		{34, "samplingInterval"},
		{35, "samplingAlgorithm"},
		{48, "samplerId"},
		{49, "samplerMode"},
		{50, "samplerRandomInterval"},
		{85, "octetTotalCount"},
		{86, "packetTotalCount"},
		{150, "flowStartSeconds"},
		{151, "flowEndSeconds"},
		{152, "flowStartMilliseconds"},
		{153, "flowEndMilliseconds"},
		{154, "flowStartMicroseconds"},
		{155, "flowEndMicroseconds"},
		{156, "flowStartNanoseconds"},
		{157, "flowEndNanoseconds"},
		{160, "systemInitTimeMilliseconds"},
		{231, "initiatorOctets"},
		{232, "responderOctets"},
		{304, "selectorAlgorithm"},
		{305, "samplingPacketInterval"},
		{306, "samplingPacketSpace"},
	}
	for _, n := range names {
		re := regexp.MustCompile(`// ` + n.name + `\n\t\w+ uint16 = ` + strconv.Itoa(n.id) + `\n`)
		if !re.Match(src) {
			t.Errorf("IE %d comment %s drifted", n.id, n.name)
		}
	}
}
