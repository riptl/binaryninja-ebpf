# Binary Ninja eBPF & Solana support

Author: **[terorie](https://github.com/terorie)**

This BN plugin implements a disassembler and lifter for the eBPF architecture and its Solana derivatives.

## Building

```shell
git submodule update --init

mkdir build
cmake . -G Ninja build
cmake --build build
```