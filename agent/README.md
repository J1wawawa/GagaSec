# J4team Gaga collection Agent

Client-generated task bundles use this Go executable with a unique task configuration. The reusable executable is not itself a uniquely compiled private client. The client retains the recipient private key in its OS credential store; task bundles contain only the recipient public key and a limited task credential.

Build all distributed templates from the repository root with `npm run build:agents` (Go 1.27.3+). Tests: `go test ./...`. Linux amd64 / arm64 and Windows amd64 are built; only Linux supports eBPF capture. This development host is macOS; real Linux kernel attachment and Windows execution have not been verified.

The eBPF socket filter accepts frames on an AF_PACKET socket. Userspace bounds parsing to snaplen while MSG_TRUNC retains the observed original frame length. It aggregates directional metadata; it does not implement PCAP retention, TCP reassembly, TLS decryption, process attribution or complete namespace coverage. Drop / unsupported / omitted counters and errors accompany windows.

Every encrypted collection body also includes bounded collection metadata: gaga-agent version/build, platform and architecture, timezone, local UTC offset, an explicit unknown clock-skew field when no receiver reference is available, declared permissions, requested file/command/network scope, and missing items with their reason and required permission. Missing, denied and truncated sources remain visible in the package; a successful envelope never means that a complete forensic collection was possible.

See the root README for collection fields, bounds, encryption format, credential limits, deployment steps and noncommercial license. Never use the public fixture private key in `fixtures/agent-interop/` for a real deployment; it exists only for cross-language tests.
