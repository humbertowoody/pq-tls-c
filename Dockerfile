# Use a base image with gcc and cmake, Ubuntu in this case
FROM ubuntu:latest

# Install necessary packages
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /usr/src/app

# Copy everything in the current directory to the working directory in the container
COPY . .

# Compile the project using make and create symbolic links in /usr/lib
RUN make && \
    ln -s /usr/src/app/libpqcrystals_kyber512_ref.so /usr/lib/libpqcrystals_kyber512_ref.so && \
    ln -s /usr/src/app/libpqcrystals_dilithium2_ref.so /usr/lib/libpqcrystals_dilithium2_ref.so

# Command to run the compiled binary
CMD ["./pq-tls-c"]
