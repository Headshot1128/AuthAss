import { readFileSync } from 'node:fs';
import { configureWasmModules } from '../vendor/hash-wasm/lib/WASMInterface.ts';

configureWasmModules(
  await WebAssembly.compile(readFileSync(new URL('../vendor/hash-wasm/argon2.wasm', import.meta.url))),
  await WebAssembly.compile(readFileSync(new URL('../vendor/hash-wasm/blake2b.wasm', import.meta.url))),
);
