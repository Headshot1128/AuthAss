import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { validateApplication, packageApplication, sha256, MAX_APPLICATION_BYTES } from '../web/assets/bootstrapper.js';
import manifest from '../lib/bootstrap-manifest.json' with {type:'json'};

function application() {
  const bytes=new Uint8Array(1024),view=new DataView(bytes.buffer);
  view.setUint16(0,0x5a4d,true);view.setUint32(0x3c,0x80,true);
  view.setUint32(0x80,0x4550,true);view.setUint16(0x84,0x8664,true);
  view.setUint16(0x94,0xf0,true);view.setUint16(0x96,2,true);view.setUint16(0x98,0x20b,true);
  bytes.set(new TextEncoder().encode('NOVYX_DLL_SDK_V1'),512);
  return bytes;
}

test('rejects non-EXEs, malformed PE offsets, DLLs, x86 and old static SDK applications',()=>{
  assert.throws(()=>validateApplication(new Uint8Array(0)),/EXE/);
  assert.throws(()=>validateApplication(new Uint8Array(MAX_APPLICATION_BYTES+1)),/64 MiB/);
  const badOffset=application();new DataView(badOffset.buffer).setUint32(0x3c,0xffffffff,true);
  assert.throws(()=>validateApplication(badOffset),/valid Windows/);
  const dll=application();new DataView(dll.buffer).setUint16(0x96,0x2002,true);
  assert.throws(()=>validateApplication(dll),/DLLs/);
  const x86=application();new DataView(x86.buffer).setUint16(0x84,0x14c,true);
  assert.throws(()=>validateApplication(x86),/x64/);
  const old=application();old.fill(0,512);
  assert.throws(()=>validateApplication(old),/Rebuild/);
});

test('package preserves all application bytes and records exact extraction boundaries',async()=>{
  const app=application(),stub=new Uint8Array([77,90,...new Uint8Array(100)]);
  const bytes=new Uint8Array(await packageApplication(stub,app).arrayBuffer());
  assert.deepEqual(bytes.slice(0,stub.length),stub);
  assert.deepEqual(bytes.slice(stub.length,-24),app);
  assert.equal(new TextDecoder().decode(bytes.slice(-24,-16)),'NVXPKG01');
  const footer=new DataView(bytes.buffer,bytes.length-24,24);
  assert.equal(footer.getBigUint64(8,true),BigInt(app.length));
  assert.equal(footer.getBigUint64(16,true),BigInt(stub.length));
});

test('non-default application packaging requires its compiled Application ID',()=>{
  const bytes=application(),id='00000000-0000-4000-8000-000000000002';
  assert.throws(()=>validateApplication(bytes,id),/Application ID/);
  bytes.set(new TextEncoder().encode(id),600);
  assert.doesNotThrow(()=>validateApplication(bytes,id));
});

test('published template matches authenticated manifest and contains DLL exports',async()=>{
  const template=new Uint8Array(readFileSync('public/bootstrap/novyx-template.bin'));
  assert.equal(template.length,manifest.template_bytes);
  assert.equal(await sha256(template),manifest.template_sha256);
  const contents=new TextDecoder('latin1').decode(template);
  assert(contents.includes('novyx_get_api_v1'));
  assert(contents.includes('novyx_auth_run'));
});
