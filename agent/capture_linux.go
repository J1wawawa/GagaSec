//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"
)

func captureRequirements() map[string]any {
	_, btf := os.Stat("/sys/kernel/btf/vmlinux")
	return map[string]any{"linux": true, "effectiveUid": os.Geteuid(), "kernelBtfPresent": btf == nil, "required": "CAP_BPF (or kernel-dependent CAP_SYS_ADMIN) and CAP_NET_RAW; no sysctl or privilege changes are made", "visibility": "configured interface in current network namespace only; no TLS decryption, TCP reassembly or PID attribution"}
}
func capture(cfg Config, w *writer) error {
	if cfg.Interface == "" {
		return errors.New("interface is required; use any for current network namespace")
	}
	program, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "gaga_observer", Type: ebpf.SocketFilter, License: "Proprietary", Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, -1), asm.Return()}})
	if err != nil {
		return fmt.Errorf("eBPF program could not load (kernel / capability / memlock policy): %w", err)
	}
	defer program.Close()
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int((uint16(unix.ETH_P_ALL)<<8)|(uint16(unix.ETH_P_ALL)>>8)))
	if err != nil {
		return fmt.Errorf("packet socket requires CAP_NET_RAW: %w", err)
	}
	defer unix.Close(fd)
	index := 0
	if cfg.Interface != "any" {
		iface, err := net.InterfaceByName(cfg.Interface)
		if err != nil {
			return err
		}
		index = iface.Index
	}
	if err = unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: (uint16(unix.ETH_P_ALL) << 8) | (uint16(unix.ETH_P_ALL) >> 8), Ifindex: index}); err != nil {
		return err
	}
	if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ATTACH_BPF, program.FD()); err != nil {
		return fmt.Errorf("attach eBPF socket filter: %w", err)
	}
	unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<20)
	unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 0, Usec: 500000})
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	expiry, _ := time.Parse(time.RFC3339, cfg.ExpiresAt)
	deadline := time.Now().Add(time.Duration(cfg.DurationSeconds) * time.Second)
	if expiry.Before(deadline) {
		deadline = expiry
	}
	buffer := make([]byte, cfg.Snaplen)
	flows := map[string]Flow{}
	start := time.Now()
	last := start
	packets := uint64(0)
	unparsed := uint64(0)
	omitted := uint64(0)
	flush := func() error {
		if packets == 0 {
			return nil
		}
		rows := make([]Flow, 0, len(flows))
		for _, flow := range flows {
			rows = append(rows, flow)
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Bytes > rows[j].Bytes })
		stats, statErr := unix.GetsockoptTpacketStats(fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
		drops := uint32(0)
		kernelPackets := uint32(0)
		if statErr == nil {
			drops = stats.Drops
			kernelPackets = stats.Packets
		}
		body := map[string]any{"windowStart": last.UTC().Format(time.RFC3339Nano), "windowEnd": time.Now().UTC().Format(time.RFC3339Nano), "interface": cfg.Interface, "flows": rows, "observedPackets": packets, "kernelPackets": kernelPackets, "kernelDrops": drops, "unparsedPackets": unparsed, "omittedFlowPackets": omitted, "snaplen": cfg.Snaplen, "httpFragmentsEnabled": cfg.IncludeHTTP, "coverage": "eBPF socket filter and AF_PACKET; aggregate metadata only, no full PCAP, IPv6 extension / noninitial fragments may be unparsed; duplicates across interfaces possible"}
		meta := collectionMetadata([]string{}, []string{"bpftool", "ip", "ss"}, "configured interface and network namespace; aggregate flow metadata", int(time.Since(last).Seconds()))
		for key, value := range meta {
			body[key] = value
		}
		if statErr != nil {
			body["statisticsError"] = statErr.Error()
		}
		err := w.save("ebpf", body)
		flows = map[string]Flow{}
		packets = 0
		unparsed = 0
		omitted = 0
		last = time.Now()
		return err
	}
	for time.Now().Before(deadline) && ctx.Err() == nil {
		n, _, err := unix.Recvfrom(fd, buffer, unix.MSG_TRUNC)
		if err != nil {
			if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
				return err
			}
		} else {
			packets++
			size := n
			if size > len(buffer) {
				size = len(buffer)
			}
			flow, ok := parsePacket(buffer[:size], n, cfg.IncludeHTTP)
			if !ok {
				unparsed++
			} else {
				key := fmt.Sprintf("%s|%d|%s|%d|%s", flow.SourceIP, flow.SourcePort, flow.DestinationIP, flow.DestinationPort, flow.Protocol)
				if old, exists := flows[key]; exists {
					old.Packets++
					old.Bytes += flow.Bytes
					if old.HTTPFragment == "" {
						old.HTTPFragment = flow.HTTPFragment
					}
					flows[key] = old
				} else if len(flows) < 2000 {
					flows[key] = flow
				} else {
					omitted++
				}
			}
		}
		if time.Since(last) >= time.Duration(cfg.BatchSeconds)*time.Second {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	return flush()
}
