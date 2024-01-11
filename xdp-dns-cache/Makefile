.PHONY: all bpf user-space run

all:
	cargo xtask build-ebpf
	cargo build

bpf:
	cargo xtask build-ebpf

user-space:
	cargo build

run:
	RUST_LOG=info cargo xtask run -- --iface lo
