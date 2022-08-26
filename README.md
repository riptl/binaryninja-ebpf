# Binary Ninja eBPF & Solana support

Author: **[terorie](https://github.com/terorie)**

This BN plugin implements a Capstone-powered disassembler and lifter for the Solana derivatives bytecode format.

Kernel eBPF support is WIP.

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

# An installation of Binary Ninja
# Use latest development build, stable is always broken
#
# macOS: /Applications/Binary Ninja.app
# Linux: ~/binaryninja
```

## Building

```shell
mkdir build

# protip: use -DHEADLESS=1 if you don't want to get Qt6
cmake -B build . -G Ninja -DBN_API_PATH=./binaryninja-api

cmake --build build
```

To install, copy or symlink `build/libarch_ebpf.so` into `~/.binaryninja/plugins`.

When starting BN, the log should display: `[Core] Loaded native plugin arch_ebpf`.
