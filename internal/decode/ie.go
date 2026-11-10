package decode

// IANA IPFIX information element numbers.
// The comment on each constant is the registry name. Parsers compare a
// field id with these constants after masking off the enterprise bit.
const (
	// octetDeltaCount
	OctetDeltaCount uint16 = 1
	// packetDeltaCount
	PacketDeltaCount uint16 = 2
	// protocolIdentifier
	ProtocolIdentifier uint16 = 4
	// ipClassOfService
	IPClassOfService uint16 = 5
	// tcpControlBits
	TCPControlBits uint16 = 6
	// sourceTransportPort
	SourceTransportPort uint16 = 7
	// sourceIPv4Address
	SourceIPv4Address uint16 = 8
	// sourceIPv4PrefixLength
	SourceIPv4PrefixLength uint16 = 9
	// ingressInterface
	IngressInterface uint16 = 10
	// destinationTransportPort
	DestinationTransportPort uint16 = 11
	// destinationIPv4Address
	DestinationIPv4Address uint16 = 12
	// destinationIPv4PrefixLength
	DestinationIPv4PrefixLength uint16 = 13
	// egressInterface
	EgressInterface uint16 = 14
	// ipNextHopIPv4Address
	IPNextHopIPv4Address uint16 = 15
	// bgpSourceAsNumber
	BGPSourceAsNumber uint16 = 16
	// bgpDestinationAsNumber
	BGPDestinationAsNumber uint16 = 17
	// flowEndSysUpTime
	FlowEndSysUpTime uint16 = 21
	// flowStartSysUpTime
	FlowStartSysUpTime uint16 = 22
	// postOctetDeltaCount
	PostOctetDeltaCount uint16 = 23
	// postPacketDeltaCount
	PostPacketDeltaCount uint16 = 24
	// sourceIPv6Address
	SourceIPv6Address uint16 = 27
	// destinationIPv6Address
	DestinationIPv6Address uint16 = 28
	// samplingInterval
	SamplingInterval uint16 = 34
	// samplingAlgorithm
	SamplingAlgorithm uint16 = 35
	// samplerId
	SamplerID uint16 = 48
	// samplerMode
	SamplerMode uint16 = 49
	// samplerRandomInterval
	SamplerRandomInterval uint16 = 50
	// flowDirection
	FlowDirection uint16 = 61
	// octetTotalCount
	OctetTotalCount uint16 = 85
	// packetTotalCount
	PacketTotalCount uint16 = 86
	// flowStartSeconds
	FlowStartSeconds uint16 = 150
	// flowEndSeconds
	FlowEndSeconds uint16 = 151
	// flowStartMilliseconds
	FlowStartMilliseconds uint16 = 152
	// flowEndMilliseconds
	FlowEndMilliseconds uint16 = 153
	// flowStartMicroseconds
	FlowStartMicroseconds uint16 = 154
	// flowEndMicroseconds
	FlowEndMicroseconds uint16 = 155
	// flowStartNanoseconds
	FlowStartNanoseconds uint16 = 156
	// flowEndNanoseconds
	FlowEndNanoseconds uint16 = 157
	// systemInitTimeMilliseconds
	SystemInitTimeMilliseconds uint16 = 160
	// initiatorOctets
	InitiatorOctets uint16 = 231
	// responderOctets
	ResponderOctets uint16 = 232
	// selectorAlgorithm
	SelectorAlgorithm uint16 = 304
	// samplingPacketInterval
	SamplingPacketInterval uint16 = 305
	// samplingPacketSpace
	SamplingPacketSpace uint16 = 306
)
