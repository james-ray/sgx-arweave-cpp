# Use the official Ubuntu image as the base for the builder
FROM ubuntu:latest as builder

# Install necessary dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Clone the sgx-arweave-cpp repository
RUN git clone https://github.com/Safeheron/sgx-arweave-cpp.git

# Change directory to sgx-arweave-cpp
WORKDIR /app/sgx-arweave-cpp

# Create build directory and compile the project
RUN mkdir build && cd build && cmake .. && make && make install

# Use a minimal base image for the runner
FROM ubuntu:latest

# Install necessary dependencies
RUN apt-get update && apt-get install -y \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy the built binary from the builder stage
COPY --from=builder /app/sgx-arweave-cpp/tee-arweave-server-0.0.1 /app/tee-arweave-server-0.0.1

# Expose the port the web server will run on
EXPOSE 8080

# Set the entry point to run the web server
ENTRYPOINT ["./tee-arweave-server-0.0.1/tee-arweave-server", "enclave.signed.so", "."]