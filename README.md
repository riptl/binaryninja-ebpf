# Binary Ninja eBPF & Solana support

Author: **[terorie](https://github.com/terorie)**

This BN plugin implements a disassembler and lifter for the eBPF architecture and its Solana derivatives.

## Dependencies

```shell
# For Capstone v5
git submodule update --init

# Binary Ninja SDK
git clone https://github.com/Vector35/binaryninja-api --depth=1

# Qt6 (macOS)
brew install qt6
# Qt6 (Debian)
apt install qt6-base-dev libgl1-mesa-dev
```

## Building

```shell
mkdir build

# protip: use -DHEADLESS=1 if you don't want to get Qt6
cmake -B build . -G Ninja -DBN_API_PATH=./binaryninja-api

cmake --build build
```
