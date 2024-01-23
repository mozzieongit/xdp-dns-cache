.PHONY: release debug run run-debug

release:
	cargo xtask build-ebpf --release
	cargo build --release

debug:
	RUSTFLAGS="--cfg include_info" cargo xtask build-ebpf
	RUSTFLAGS="--cfg include_info" cargo build

run: release
	sudo RUST_LOG=info target/release/xdp-dns-cache --iface lo

run-debug: debug
	sudo RUST_LOG=info target/debug/xdp-dns-cache --iface lo
