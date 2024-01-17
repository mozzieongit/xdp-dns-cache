.PHONY: all bpf user-space run

all: bpf user-space

bpf:
	cargo xtask build-ebpf

user-space:
	cargo build

release:
	cargo xtask build-ebpf --release
	cargo build --release

run:
	RUST_LOG=info cargo xtask run -- --iface lo
