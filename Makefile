# Detect the operating system
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
    # macOS
    OPENSSL_PATH=/opt/homebrew/opt/openssl
endif
ifeq ($(UNAME_S),Linux)
    # Linux (default path for many distros)
    OPENSSL_PATH=/usr/include/openssl
endif

# Define compiler and flags
CC=gcc
CFLAGS=-I./kyber/ref -I./dilithium/ref -I$(OPENSSL_PATH)/include #-Wall -Wextra -Werror -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -Wno-unused-but-set-variable -Wno-unused-value -Wno-unused-result -Wno-unused-label -Wno-unused-local-typedefs
LDFLAGS=-L./ -lpqcrystals_kyber512_ref -lpqcrystals_dilithium2_ref -L$(OPENSSL_PATH)/lib -lcrypto -lssl
EXECUTABLE=pq-tls-c.out

# Define all targets
all: kyber_lib dilithium_lib main

# Build Kyber
kyber_lib:
	cd kyber/ref && make shared
	cp kyber/ref/libpqcrystals_kyber512_ref.so .

# Build Dilithium
dilithium_lib:
	cd dilithium/ref && make shared
	cp dilithium/ref/libpqcrystals_dilithium2_ref.so .

# Compile your main program
main: main.c
	$(CC) $(CFLAGS) main.c $(LDFLAGS) -o $(EXECUTABLE)

# Clean the build
clean:
	cd kyber/ref && make clean
	cd dilithium/ref && make clean
	rm -f $(EXECUTABLE)
	rm -f libpqcrystals_kyber512_ref.so
	rm -f libpqcrystals_dilithium2_ref.so
