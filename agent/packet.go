package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

type Flow struct {
	SourceIP        string `json:"sourceIp"`
	DestinationIP   string `json:"destinationIp"`
	SourcePort      uint16 `json:"sourcePort"`
	DestinationPort uint16 `json:"destinationPort"`
	Protocol        string `json:"protocol"`
	Packets         uint64 `json:"packets"`
	Bytes           uint64 `json:"bytes"`
	HTTPFragment    string `json:"httpFragment,omitempty"`
}

func parsePacket(packet []byte, wireBytes int, httpFragment bool) (Flow, bool) {
	var flow Flow
	if len(packet) < 14 || wireBytes < len(packet) {
		return flow, false
	}
	offset := 14
	ether := binary.BigEndian.Uint16(packet[12:14])
	for i := 0; i < 2 && (ether == 0x8100 || ether == 0x88a8); i++ {
		if len(packet) < offset+4 {
			return flow, false
		}
		ether = binary.BigEndian.Uint16(packet[offset+2 : offset+4])
		offset += 4
	}
	var protocol byte
	end := len(packet)
	datagramEnd := 0
	fragmented := false
	if ether == 0x0800 {
		if len(packet) < offset+20 || packet[offset]>>4 != 4 {
			return flow, false
		}
		ihl := int(packet[offset]&15) * 4
		if ihl < 20 || len(packet) < offset+ihl {
			return flow, false
		}
		total := int(binary.BigEndian.Uint16(packet[offset+2 : offset+4]))
		if total < ihl || offset+total > wireBytes {
			return flow, false
		}
		datagramEnd = offset + total
		// Snaplen can truncate a valid datagram; padding beyond its declared
		// length is never application evidence. Header checks below use this bound.
		if offset+total < end {
			end = offset + total
		}
		if binary.BigEndian.Uint16(packet[offset+6:offset+8])&0x1fff != 0 {
			return flow, false
		}
		fragmented = binary.BigEndian.Uint16(packet[offset+6:offset+8])&0x2000 != 0
		protocol = packet[offset+9]
		flow.SourceIP = net.IP(packet[offset+12 : offset+16]).String()
		flow.DestinationIP = net.IP(packet[offset+16 : offset+20]).String()
		offset += ihl
	} else if ether == 0x86dd {
		if len(packet) < offset+40 || packet[offset]>>4 != 6 {
			return flow, false
		}
		payloadLength := int(binary.BigEndian.Uint16(packet[offset+4 : offset+6]))
		if payloadLength == 0 || offset+40+payloadLength > wireBytes {
			return flow, false // IPv6 jumbograms require unsupported extension headers.
		}
		datagramEnd = offset + 40 + payloadLength
		if offset+40+payloadLength < end {
			end = offset + 40 + payloadLength
		}
		protocol = packet[offset+6]
		if protocol == 0 || protocol == 43 || protocol == 44 || protocol == 50 || protocol == 51 || protocol == 60 {
			return flow, false
		}
		flow.SourceIP = net.IP(packet[offset+8 : offset+24]).String()
		flow.DestinationIP = net.IP(packet[offset+24 : offset+40]).String()
		offset += 40 // Extension headers are explicitly unsupported and counted as unparsed.
	} else {
		return flow, false
	}
	packet = packet[:end]
	switch protocol {
	case 6:
		flow.Protocol = "tcp"
		if len(packet) < offset+20 {
			return flow, false
		}
		flow.SourcePort = binary.BigEndian.Uint16(packet[offset : offset+2])
		flow.DestinationPort = binary.BigEndian.Uint16(packet[offset+2 : offset+4])
		header := int(packet[offset+12]>>4) * 4
		if header < 20 || len(packet) < offset+header {
			return flow, false
		}
		offset += header
		if httpFragment {
			payload := packet[offset:]
			if len(payload) > 256 {
				payload = payload[:256]
			}
			line := strings.SplitN(string(payload), "\r\n", 2)[0]
			if strings.HasPrefix(line, "GET ") || strings.HasPrefix(line, "POST ") || strings.HasPrefix(line, "HEAD ") || strings.HasPrefix(line, "HTTP/1.") {
				flow.HTTPFragment = strings.Map(func(r rune) rune {
					if r < 32 || r > 126 {
						return -1
					}
					return r
				}, line)
			}
		}
	case 17:
		flow.Protocol = "udp"
		if len(packet) < offset+8 {
			return flow, false
		}
		length := int(binary.BigEndian.Uint16(packet[offset+4 : offset+6]))
		if length < 8 || !fragmented && offset+length > datagramEnd {
			return flow, false
		}
		flow.SourcePort = binary.BigEndian.Uint16(packet[offset : offset+2])
		flow.DestinationPort = binary.BigEndian.Uint16(packet[offset+2 : offset+4])
	case 1:
		flow.Protocol = "icmp"
	case 58:
		flow.Protocol = "icmpv6"
	default:
		flow.Protocol = fmt.Sprintf("ip-%d", protocol)
	}
	flow.Packets = 1
	flow.Bytes = uint64(wireBytes)
	return flow, true
}
