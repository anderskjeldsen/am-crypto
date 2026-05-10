# am-crypto

Cryptographic primitives for the Am programming language.

## Overview

`am-crypto` is a focused crypto package extracted from `am-ssl`.

It currently provides one primitive:

- `Am.Crypto.Sha1` with `Sha1.digest(input: UByte[]): UByte[]`

This split lets projects that only need hashing (for legacy protocol compatibility) avoid pulling in the full SSL/TLS socket layer from `am-ssl`.

## Why this package exists

Some protocols still require SHA-1 for interoperability (for example, `mysql_native_password` and Git object IDs), even though SHA-1 should not be used for new password storage or signature designs. `am-crypto` keeps this use case isolated and explicit.

## Installation

Add `am-crypto` to your `package.yml` dependencies:

```yaml
dependencies:
  - id: am-crypto
		realm: github
		type: git-repo
		tag: latest
		url: https://github.com/anderskjeldsen/am-crypto.git
```

## API

Namespace:

- `Am.Crypto`

Class:

- `Sha1`

Method:

- `static native fun digest(input: UByte[]): UByte[]`

Behavior:

- Returns a new 20-byte SHA-1 digest (`UByte[]`) for the input bytes.

Example:

```am
namespace Example {
	class Program {
		import Am.Lang
		import Am.Crypto

		static fun main() {
			var bytes: UByte[] = "abc".toBytes("UTF-8")
			var digest: UByte[] = Sha1.digest(bytes)
			("digest length = " + digest.length().toString()).println() // 20
		}
	}
}
```

## Platform implementation notes

- `libc` platforms (`linux-x64`, `macos`, `macos-arm`, `morphos-ppc`) use OpenSSL/libcrypto.
- `amigaos` (m68k) uses AmiSSL with explicit init support files.
- This package links only crypto functionality (`libcrypto`/AmiSSL) and does not provide SSL socket streams.

## Build

From project root:

```bash
make build
```

Useful targets:

- `make build` (host platform)
- `make build-linux-x64`
- `make build-macos-arm`
- `make build-amigaos`

## Test

Run package tests:

```bash
make test
```

## Examples

Available examples:

- `examples/sha1-test` (AmLang usage)
- `examples/sha1-c-test` (native C SHA-1 check for comparison)

To build an example, for instance:

```bash
cd examples/sha1-test
make build
```

## Repository

GitHub: https://github.com/anderskjeldsen/am-crypto.git
