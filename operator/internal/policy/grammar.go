// Package policy: canonical rendering of daemon policy rule literals.
package policy

import (
	"fmt"
	"strings"
)

// --- Canonical daemon policy grammar -------------------------------------
//
// The daemon parser (src/policy_parse.cpp, mirrored byte-for-byte by
// rust/aegis-parser/src/policy.rs) accepts exactly these forms:
//
//	[deny_port]     PORT[:PROTOCOL[:DIRECTION]]
//	[deny_ip_port]  IP:PORT[:PROTOCOL]          (IPv6 must be bracketed)
//
// PROTOCOL is one of tcp | udp | any; DIRECTION is one of
// egress | connect | bind | both. Both trailing fields are optional in the
// grammar, but the operator always emits them fully qualified so that a
// policy's meaning never depends on which side's default applies.
//
// DIRECTION is socket-operation semantics, not packet direction:
// egress/connect covers connect()/sendmsg(), bind covers bind()/listen().
// The CRD's outbound/inbound vocabulary maps onto that, matching the
// mapping translator_next.go already performs for aegis-next.

const (
	// defaultCRDProtocol is the protocol assumed when NetworkRule.Protocol
	// is unset. The admission webhook and translator_next.go resolve the
	// same default, so all three agree on what an unset field means.
	defaultCRDProtocol = "tcp"
	// defaultCRDDirection is the direction assumed when
	// NetworkRule.Direction is unset.
	defaultCRDDirection = "outbound"
)

// daemonProtocol maps a CRD protocol value onto the daemon token.
func daemonProtocol(p string) (string, error) {
	switch p {
	case "":
		return defaultCRDProtocol, nil
	case "tcp", "udp", "any":
		return p, nil
	default:
		return "", fmt.Errorf("unsupported protocol %q (want tcp, udp or any)", p)
	}
}

// daemonDirection maps the CRD's traffic-direction vocabulary onto the
// daemon's socket-operation vocabulary.
//
// "inbound" lowers to "bind", which covers bind()/listen() on a local port.
// It does not cover accept() of an already-bound socket; the daemon has no
// port rule that discriminates accepted peers.
func daemonDirection(d string) (string, error) {
	switch d {
	case "":
		return daemonDirection(defaultCRDDirection)
	case "outbound":
		return "egress", nil
	case "inbound":
		return "bind", nil
	case "both":
		return "both", nil
	default:
		return "", fmt.Errorf("unsupported direction %q (want outbound, inbound or both)", d)
	}
}

// CanonicalPortRule renders a [deny_port]/[allow_port] literal as
// PORT:PROTOCOL:DIRECTION.
func CanonicalPortRule(port int, protocol, direction string) (string, error) {
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("port %d out of range 1-65535", port)
	}
	proto, err := daemonProtocol(protocol)
	if err != nil {
		return "", err
	}
	dir, err := daemonDirection(direction)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d:%s:%s", port, proto, dir), nil
}

// CanonicalIPPortRule renders a [deny_ip_port] literal as IP:PORT:PROTOCOL.
//
// The daemon's IpPortRule carries no direction field, so the CRD's
// direction is deliberately dropped here: an ip+port rule applies to every
// hook that evaluates a remote tuple. For a Block rule that is a widening
// (safe); Allow rules never reach the daemon at all.
//
// IPv6 literals are bracketed, matching format_ip_port_rule() in
// src/network_ops.cpp. Without brackets "::1:443" is ambiguous — it is
// itself a valid IPv6 address as well as ::1 port 443.
func CanonicalIPPortRule(ip string, port int, protocol string) (string, error) {
	if ip == "" {
		return "", fmt.Errorf("ip must not be empty")
	}
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("port %d out of range 1-65535", port)
	}
	proto, err := daemonProtocol(protocol)
	if err != nil {
		return "", err
	}
	literal := ip
	if strings.Contains(ip, ":") {
		literal = "[" + ip + "]"
	}
	return fmt.Sprintf("%s:%d:%s", literal, port, proto), nil
}
