all: ctarget/target/release/libcuriefense.so

ctarget:
	mkdir ctarget

ctarget/registry: ctarget
	mkdir -p ctarget/registry

ctarget/target: ctarget
	mkdir -p ctarget/target

ctarget/target/release/libcuriefense.so: container ctarget/registry ctarget/target
	docker run -v `pwd`:/home/builder/rust -v `pwd`/ctarget/registry:/home/builder/.cargo/registry  -w /home/builder/rust  -t curiefense/rustbuild:latest /home/builder/.cargo/bin/cargo build --release --target-dir ctarget/target

../lua/shared-objects/curiefense.so: ctarget/target/release/libcuriefense.so
	cp ctarget/target/release/libcuriefense.so ../lua/shared-objects/curiefense.so

.PHONY: all container

container:
	tar c Dockerfile  |  docker build -t curiefense/rustbuild -f Dockerfile -

