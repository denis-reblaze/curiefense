all: ctarget/target/release/libcuriefense.so

ctarget:
	mkdir ctarget

ctarget/registry: container ctarget
	mkdir -p ctarget/registry

ctarget/target: container ctarget
	mkdir -p ctarget/target

ctarget/target/release/libcuriefense.so: container ctarget/registry ctarget/target
	docker run -v `pwd`:/home/builder/rust -v `pwd`/ctarget/registry:/home/builder/.cargo/registry  -w /home/builder/rust  -t curiefense/rustbuild:latest /home/builder/.cargo/bin/cargo build --target-dir ctarget/target

.PHONY: all container

container:
	tar c Dockerfile  |  docker build -t curiefense/rustbuild -f Dockerfile -

