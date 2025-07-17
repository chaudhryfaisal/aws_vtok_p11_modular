build:
	cargo build
clean:
	cargo clean
aws-lc:
	@set -e; \
	echo "Installing dependencies..."; \
	apt update && apt install -y git cmake ninja-build build-essential perl python3 python3-pip; \
	echo "Cloning aws-lc..."; \
	rm -rf /tmp/aws-lc && git clone --depth 1 https://github.com/aws/aws-lc.git /tmp/aws-lc; \
	cd /tmp/aws-lc && mkdir build && cd build; \
	echo "Configuring build..."; \
	cmake .. -GNinja -DCMAKE_BUILD_TYPE=Release; \
	echo "Building..."; \
	ninja; \
	echo "Installing..."; \
	ninja install; \
	ldconfig; \
	echo "AWS-LC installed successfully."
