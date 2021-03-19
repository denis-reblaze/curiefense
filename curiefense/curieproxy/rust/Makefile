all: target/debug/libcuriefense.so

target/debug/libcuriefense.so: src/lib.rs src/config.rs Cargo.toml
	cargo build
	cp target/debug/libcuriefense.so ../mounts/5.1/curiedefense.so

.PHONY: all
