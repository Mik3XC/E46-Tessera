# Building locally

Platform walkthroughs: [macOS (OS X)](../build.md) · [Linux](../LINUX.md).
Current development and successful compilation are on macOS 26.3 / arm64.
Linux has not yet been verified.

## Requirements

- POSIX platform. This copy was prepared on macOS; Linux needs separate validation.
- C++20 compiler with `__int128` (Clang or GCC).
- CMake 3.21 or newer and Ninja.
- OpenSSL **3.6.5**, including development headers and `libcrypto`.

The exact OpenSSL pin preserves the seeded SLH-DSA behavior used by the wallet.
Key generation also runs an embedded known-answer self-check. Changing that pin
requires compatibility review; removing the check is not a dependency upgrade.

On Apple Silicon, CMake recognizes an existing `/opt/homebrew/opt/openssl@3`
installation. Elsewhere, set the installed dependency path explicitly:

```sh
cmake --preset dev -DOPENSSL_ROOT_DIR=/path/to/openssl-3.6.5
cmake --build --preset dev
```

## Presets

| Preset | Output | Purpose |
| --- | --- | --- |
| `dev` | `build/dev/` | Node, wallet, address and transaction CLIs |
| `tools` | `build/tools/` | Default programs plus primitive diagnostic CLIs |
| `sanitize` | `build/sanitize/` | Default programs with ASan/UBSan instrumentation |

```sh
cmake --preset tools
cmake --build --preset tools
```

This source-only staging tree does not include the separate GOLD/differential
test collection. Building is not a substitute for running those checks or
reviewing consensus behavior. The new standalone Python P2P exercise is
documented in [P2P.md](P2P.md); it is not run during a build. No release,
packaging, installation, or publishing target is configured.

Only ignored local build products are created. No wallets, mining jobs, or
network services start during the build.
