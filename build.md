# Build E46 Tessera

## Development platform: macOS (OS X)

The project is currently developed on a Mac. The `dev` and `tools` builds
completed successfully with this local toolchain on October 10, 2026:

| Component | Observed version |
| --- | --- |
| macOS | 26.3 |
| Architecture | Apple Silicon / arm64 |
| Compiler | Apple Clang 21.0.0 |
| CMake | 4.3.2 |
| Ninja | 1.13.2 |
| OpenSSL | 3.6.5 |

This records successful compilation, not a full test run. Linux readers should
use [LINUX.md](LINUX.md); Linux execution remains unverified.

## 1. Prepare the Mac toolchain

If Command Line Tools are missing, request their installation:

```sh
xcode-select --install
```

With Homebrew already installed, install missing build tools:

```sh
brew install cmake ninja
```

The project requires **OpenSSL 3.6.5 exactly**, with headers and `libcrypto`.
Check an existing Homebrew installation:

```sh
E46_OPENSSL="$(brew --prefix openssl@3)"
"$E46_OPENSSL/bin/openssl" version
```

The [Homebrew openssl@3 formula](https://formulae.brew.sh/formula/openssl@3)
changes over time; `brew install openssl@3` does not guarantee version 3.6.5.
Use it only when that formula supplies the required version. Otherwise install
3.6.5 separately from the [official OpenSSL sources](https://openssl-library.org/source/)
and set `E46_OPENSSL` to that installation's absolute prefix.

Keep the exact pin and the built-in seeded-keygen self-check. A dependency
upgrade needs a separate compatibility review.

## 2. Configure and build

On the current development Mac:

```sh
cd "$HOME/Documents/E46Tessera"
E46_OPENSSL="$(brew --prefix openssl@3)"
cmake --preset dev -DOPENSSL_ROOT_DIR="$E46_OPENSSL"
cmake --build --preset dev
```

For another checkout location, adjust `cd`. If using a separate OpenSSL prefix,
retain that value of `E46_OPENSSL` instead of assigning the Homebrew prefix.
CMake stops if the detected version differs from 3.6.5.

Programs are written to `build/dev/`:

- `e46-node`
- `e46-wallet`
- `addresses_cli`
- `transaction_cli`

The explicit prefix also works with Intel Homebrew layouts. Intel macOS has not
been built here. Minimum project requirements and preset details are in
[docs/BUILD.md](docs/BUILD.md).

## 3. Optional diagnostic programs

```sh
cmake --preset tools -DOPENSSL_ROOT_DIR="$E46_OPENSSL"
cmake --build --preset tools
```

These programs are written to `build/tools/`. For an instrumented development
build, use `sanitize` instead of `dev` in both CMake commands. The sanitizer
preset was not executed as part of preparing this copy.

## 4. Start a local experiment

Follow [docs/LOCAL.md](docs/LOCAL.md) for wallet and node commands. Keep wallet
files, fingerprints, and chain data outside the source tree. The height-268
checkpoint remains enforced.

There are no packaged releases, publishing steps, or bundled GOLD test suites.
Build outputs are excluded by `.gitignore`.
