package socks5

import "fmt"

// A Reply represents a SOCKS command reply code.
// See: https://tools.ietf.org/html/rfc1928
type Reply int

const (
	// StatusSucceeded repserents successed to reply.
	StatusSucceeded Reply = iota
	// StatusServerFailure :
	StatusServerFailure
	// StatusNotAllowedByRuleSet :
	StatusNotAllowedByRuleSet
	// StatusNetworkUnreachable :
	StatusNetworkUnreachable
	// StatusHostUnreachable :
	StatusHostUnreachable
	// StatusConnectionRefused :
	StatusConnectionRefused
	// StatusTTLExpired :
	StatusTTLExpired
	// StatusCommandNotSupported :
	StatusCommandNotSupported
	// StatusAddrTypeNotSupported :
	StatusAddrTypeNotSupported
)

func (code Reply) String() string {
	switch code {
	case StatusSucceeded:
		return "succeeded"
	case StatusServerFailure:
		return "general SOCKS server failure"
	case StatusNotAllowedByRuleSet:
		return "connection not allowed by ruleset"
	case StatusNetworkUnreachable:
		return "network unreachable"
	case StatusHostUnreachable:
		return "host unreachable"
	case StatusConnectionRefused:
		return "connection refused"
	case StatusTTLExpired:
		return "TTL expired"
	case StatusCommandNotSupported:
		return "command not supported"
	case StatusAddrTypeNotSupported:
		return "address type not supported"
	default:
		return fmt.Sprintf("unknown code: %d", code)
	}
}
