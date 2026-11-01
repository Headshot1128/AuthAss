// @ts-nocheck -- vendored hash-wasm 4.12.0; see ../UPSTREAM.md
import { type IWASMInterface, WASMInterface } from "./WASMInterface.ts";
import type Mutex from "./mutex.ts";
import type { IEmbeddedWasm } from "./util.ts";

export default async function lockedCreate(
	mutex: Mutex,
	binary: IEmbeddedWasm,
	hashLength: number,
): Promise<IWASMInterface> {
	const unlock = await mutex.lock();
	const wasm = await WASMInterface(binary, hashLength);
	unlock();
	return wasm;
}
