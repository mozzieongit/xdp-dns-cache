# xdp-dns-cache

Make targets:

- **release**: build code without BPF logging
- **debug**: build code with BPF logging enabled
- **run**: build and run code without BPF logging on interface 'lo'
- **run-debug**: build and run code with BPF logging enabled on interface 'lo'

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Run

```bash
RUST_LOG=info cargo xtask run
```
