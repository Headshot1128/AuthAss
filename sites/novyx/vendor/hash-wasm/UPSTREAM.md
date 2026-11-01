# hash-wasm 4.12.0

Source: https://github.com/Daninet/hash-wasm/tree/v4.12.0
Package: https://registry.npmjs.org/hash-wasm/-/hash-wasm-4.12.0.tgz
License: MIT, included in `LICENSE`.

The TypeScript files are from the versioned npm package. The two WASM modules are
decoded without modification from the package's `dist/argon2.umd.min.js` embedded
modules. The package's SHA-512 integrity was checked before extraction:

`sha512-+/2B2rYLb48I/evdOIhP+K/DD2ca2fgBjp6O+GBEnCDk2e4rpeXIK8GvIyRPjTezgmWn9gmKwkQjjx6BtqDHVQ==`

- argon2.wasm SHA-256: 83b5829d20b4312aca1a56819f95eef20492e058c70f282c9ed6929f579b20ed
- blake2b.wasm SHA-256: b478c0d889d97d7a8db4d10501457ad78dd406d02dcb4c892c0d844805ef05bb

Local adaptations: explicit `.ts` imports for Node's test runner; type checking
disabled for unmodified upstream typing conventions; embedded JSON descriptors
replaced with names and build hashes; WASMInterface receives statically imported
Worker modules rather than compiling bytes at runtime. The serialized password
service reuses one Argon2 allocation to stay within Worker memory limits, and
clears its scratch memory after every operation. Blake2b instances remain separate.
Argon2 computations and password parameters are unchanged.
