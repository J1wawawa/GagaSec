package main

import (
	"encoding/binary"
	"testing"
)

func testPacket() []byte {
	p := make([]byte, 14+20+20)
	binary.BigEndian.PutUint16(p[12:14], 0x0800)
	p[14] = 0x45
	p[23] = 6
	copy(p[26:30], []byte{192, 0, 2, 1})
	copy(p[30:34], []byte{203, 0, 113, 2})
	binary.BigEndian.PutUint16(p[34:36], 34567)
	binary.BigEndian.PutUint16(p[36:38], 80)
	p[46] = 0x50
	p = append(p, []byte("GET /fixture HTTP/1.1\r\nHost: example.test\r\n\r\n")...)
	binary.BigEndian.PutUint16(p[16:18], uint16(len(p)-14))
	return p
}
func TestPacketParsingAndCaptureLimits(t *testing.T) {
	p := testPacket()
	f, ok := parsePacket(p, 1500, false)
	if !ok || f.SourceIP != "192.0.2.1" || f.DestinationPort != 80 || f.Bytes != 1500 || f.HTTPFragment != "" {
		t.Fatalf("flow %#v", f)
	}
	f, ok = parsePacket(p, 1500, true)
	if !ok || f.HTTPFragment != "GET /fixture HTTP/1.1" {
		t.Fatal(f)
	}
	if _, ok := parsePacket(p[:40], 1500, true); ok {
		t.Fatal("truncated header accepted")
	}
	p[20] = 0
	p[21] = 1
	if _, ok := parsePacket(p, 1500, true); ok {
		t.Fatal("noninitial fragment accepted")
	}
}
func TestIPv6ExtensionAndMalformedPackets(t *testing.T) {
	p := make([]byte, 14+40)
	binary.BigEndian.PutUint16(p[12:14], 0x86dd)
	p[14] = 0x60
	p[20] = 0
	if _, ok := parsePacket(p, 54, false); ok {
		t.Fatal("extension headers must be counted unparsed")
	}
	for i := 0; i < 80; i++ {
		parsePacket(make([]byte, i), i, true)
	}
}

func TestAudit071IPLengthsBoundHTTPAndTransport(t *testing.T) {
	p := testPacket()
	// Ethernet padding after the declared IP datagram is not an HTTP request.
	binary.BigEndian.PutUint16(p[16:18], 40)
	f, ok := parsePacket(p, len(p), true)
	if !ok || f.HTTPFragment != "" {
		t.Fatalf("Ethernet padding was treated as HTTP evidence: %#v %v", f, ok)
	}
	binary.BigEndian.PutUint16(p[16:18], 25)
	if _, ok := parsePacket(p, len(p), true); ok {
		t.Fatal("TCP header outside declared IPv4 datagram accepted")
	}
	p = make([]byte, 14+40+20+24)
	binary.BigEndian.PutUint16(p[12:14], 0x86dd)
	p[14], p[20], p[66] = 0x60, 6, 0x50
	binary.BigEndian.PutUint16(p[18:20], 20)
	copy(p[74:], "GET /padding HTTP/1.1\r\n")
	if f, ok := parsePacket(p, len(p), true); !ok || f.HTTPFragment != "" {
		t.Fatal("IPv6 padding was treated as HTTP evidence", f, ok)
	}
	p = make([]byte, 14+20+8)
	binary.BigEndian.PutUint16(p[12:14], 0x0800)
	p[14], p[23] = 0x45, 17
	binary.BigEndian.PutUint16(p[16:18], 28)
	binary.BigEndian.PutUint16(p[38:40], 7)
	if _, ok := parsePacket(p, len(p), false); ok {
		t.Fatal("invalid UDP length accepted")
	}
	binary.BigEndian.PutUint16(p[38:40], 40)
	if _, ok := parsePacket(p, len(p)+64, false); ok {
		t.Fatal("UDP length outside IP datagram accepted")
	}
	binary.BigEndian.PutUint16(p[38:40], 8)
	if f, ok := parsePacket(p, len(p), false); !ok || f.Protocol != "udp" {
		t.Fatal("valid UDP rejected", f, ok)
	}
	p = testPacket()
	// Snaplen shortens the captured slice; wire length and IP length remain valid.
	if f, ok := parsePacket(p[:60], len(p), true); !ok || f.Protocol != "tcp" || f.Bytes != uint64(len(p)) {
		t.Fatal("valid snaplen-truncated packet rejected", f, ok)
	}
	binary.BigEndian.PutUint16(p[16:18], uint16(len(p)+100))
	if _, ok := parsePacket(p, len(p), false); ok {
		t.Fatal("declared IP length beyond wire length accepted")
	}
	p = testPacket()
	vlan := append([]byte{}, p[:12]...)
	vlan = append(vlan, 0x81, 0, 0, 1)
	vlan = append(vlan, p[12:]...)
	if f, ok := parsePacket(vlan, len(vlan), true); !ok || f.HTTPFragment != "GET /fixture HTTP/1.1" {
		t.Fatal("valid VLAN request rejected", f, ok)
	}
}
