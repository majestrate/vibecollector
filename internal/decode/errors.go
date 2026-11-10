// Package decode converts sysUpTime stamps into absolute flow times and
// reports a datagram that failed a structural check.
package decode

import "errors"

// ErrMalformed means a datagram failed a structural check.
// v5.Parse returns it when the version is not 5, the header is shorter than
// 24 bytes, the count is outside 1–30, or the payload is shorter than
// 24+count*48. The returned delta is still set: Version 5 when a v5 header
// was long enough to read, and Version 0 when it was not.
// errors.Is reports this sentinel. A successful parse does not return it.
var ErrMalformed = errors.New("malformed datagram")

// ErrShortSet means a v9 or IPFIX set length is less than 4 or extends past
// the payload. Records from earlier complete sets are still returned.
// Malformed has already been incremented once. errors.Is reports this sentinel.
var ErrShortSet = errors.New("set length extends past payload")

// ErrNilDep means NewSession was given a nil cache, hold buffer, sequence
// table, or counters. errors.Is reports this sentinel.
var ErrNilDep = errors.New("nil dependency")

// ErrBadTimeout means ExpireIdle was called with a non-positive idle.
// Nothing is dropped. errors.Is reports this sentinel.
var ErrBadTimeout = errors.New("non-positive idle timeout")
