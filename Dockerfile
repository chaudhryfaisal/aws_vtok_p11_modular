# ---- Stage 1: Build AWS-LC ----
FROM debian:12 as builder

RUN apt update && apt install -y \
    git cmake ninja-build build-essential \
    perl python3 python3-pip && \
    rm -rf /var/lib/apt/lists/*

# Clone and build AWS-LC
WORKDIR /build/aws-lc
RUN git clone --depth 1 https://github.com/aws/aws-lc.git . && \
    mkdir build && cd build && \
    cmake .. -GNinja -DCMAKE_BUILD_TYPE=Release && \
    ninja

# ---- Stage 2: Final minimal image ----
FROM debian:12-slim

RUN apt update && apt install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy built libraries and headers from builder
COPY --from=builder /build/aws-lc/build/libssl.so /usr/local/lib/libssl.so
COPY --from=builder /build/aws-lc/build/libcrypto.so /usr/local/lib/libcrypto.so
COPY --from=builder /build/aws-lc/include /usr/local/include

# Optional: update linker cache
RUN ldconfig

# Set workdir
WORKDIR /app

# You can now COPY your application here and compile/link with AWS-LC


