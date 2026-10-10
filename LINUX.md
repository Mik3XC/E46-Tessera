# Building E46 Tessera on Linux

**Status: instructions prepared; Linux build and runtime not yet verified.**
The current development host is macOS. This guide targets a native 64-bit Linux
environment with GCC or Clang, C++20, and `__int128` support.

## 1. Install build prerequisites

For Debian/Ubuntu-family distributions:

```sh
sudo apt update
sudo apt install build-essential cmake ninja-build pkg-config perl libtext-template-perl ca-certificates
```

On other distributions, install the equivalent C/C++ development toolchain,
CMake, Ninja, pkg-config, and Perl packages. Check their versions:

```sh
c++ --version
cmake --version
ninja --version
```

CMake must be at least 3.21; the compiler must support C++20 and `__int128`.
Older distribution packages may require a newer toolchain.

## 2. Provide OpenSSL 3.6.5

E46 pins **OpenSSL 3.6.5 exactly**. A distribution's default `libssl-dev` or
`openssl-devel` may supply a different version. Keep system OpenSSL intact and
use a separate prefix when necessary.

Obtain the 3.6.5 source archive and verify it using the checksum/signature
published with the [official OpenSSL downloads](https://openssl-library.org/source/).
From the extracted source directory:

```sh
E46_OPENSSL="$HOME/.local/opt/openssl-3.6.5"
./Configure --prefix="$E46_OPENSSL" --openssldir="$E46_OPENSSL/ssl" --libdir=lib shared
make -j2
make install_sw
```

These commands install under your home directory. For the separately installed
OpenSSL executable, scope the library search path to this invocation:

```sh
LD_LIBRARY_PATH="$E46_OPENSSL/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
  "$E46_OPENSSL/bin/openssl" version
```

Confirm the output identifies 3.6.5. This procedure follows the upstream
[OpenSSL installation instructions](https://raw.githubusercontent.com/openssl/openssl/master/INSTALL.md);
consult the `INSTALL.md` supplied in the downloaded version for platform details.

## 3. Build the project

From your E46Tessera checkout:

```sh
cd /path/to/E46Tessera
E46_OPENSSL="$HOME/.local/opt/openssl-3.6.5"
cmake --preset dev \
  -DOPENSSL_ROOT_DIR="$E46_OPENSSL" \
  -DOPENSSL_INCLUDE_DIR="$E46_OPENSSL/include" \
  -DOPENSSL_CRYPTO_LIBRARY="$E46_OPENSSL/lib/libcrypto.so" \
  -DCMAKE_BUILD_RPATH="$E46_OPENSSL/lib"
cmake --build --preset dev
```

Replace the prefix if OpenSSL is installed elsewhere. The explicit include and
library paths keep CMake from mixing system headers with the separate library.
The build RPATH lets locally built programs find that library without changing
the system-wide linker configuration. Keep the dependency at that path.

The build produces `e46-node`, `e46-wallet`, `addresses_cli`, and
`transaction_cli` under `build/dev/`. The project does not require Qt or Python
for this CLI build.

## 4. Optional tools

For the cryptographic diagnostic CLIs, use the same dependency paths with:

```sh
cmake --preset tools \
  -DOPENSSL_ROOT_DIR="$E46_OPENSSL" \
  -DOPENSSL_INCLUDE_DIR="$E46_OPENSSL/include" \
  -DOPENSSL_CRYPTO_LIBRARY="$E46_OPENSSL/lib/libcrypto.so" \
  -DCMAKE_BUILD_RPATH="$E46_OPENSSL/lib"
cmake --build --preset tools
```

Outputs go under `build/tools/`. The `sanitize` preset uses address and
undefined-behavior sanitizers when the selected compiler supports them.

## 5. Local operation

Use [docs/LOCAL.md](docs/LOCAL.md) for node and wallet commands. Data directories
and wallet paths are explicit; choose Linux paths outside the checkout.

- The node is a local CLI, with no P2P network or HTTP service.
- A fresh store initializes the frozen genesis. Independently mined histories
  cannot cross the pinned height-268 block with a different ID.
- Keep the saved wallet fingerprint separate from the wallet file.
- The node stops disk-writing operations when available space is below 1 GiB.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| OpenSSL version rejected | Supply 3.6.5 headers and library from the same prefix. |
| `libcrypto.so.3` not found | Check the dependency still exists and configure with the build RPATH above. |
| Compiler rejects `__int128` or C++20 | Select a compatible native 64-bit GCC/Clang toolchain in a fresh build directory. |
| SLH-DSA provider/self-check error | Check the loaded library and provider configuration; keep the self-check enabled. |
| Checkpoint mismatch at 268 | The datadir contains a different chain history; see the checkpoint policy. |

No Linux success claim, test result, release package, or installation on this
Mac is implied by these instructions. The separate GOLD/differential suite is
not bundled in this tree.
