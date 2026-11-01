import './wasm-setup.mjs';
import { performance } from 'node:perf_hooks';
import { argon2idAsync } from '@noble/hashes/argon2.js';
import { verifyPassword } from '../lib/novyx-crypto.ts';
import vectors from './password-vectors.json' with {type:'json'};

const vector=vectors[0],password=new TextEncoder().encode(vector.password);
const salt=Buffer.from(vector.encoded.split('$')[4],'base64');
const median=values=>values.sort((a,b)=>a-b)[Math.floor(values.length/2)];
async function measure(operation){
  const times=[];
  for(let i=0;i<3;i++){const start=performance.now();await operation();times.push(performance.now()-start);}
  return Math.round(median(times));
}
const before=await measure(()=>argon2idAsync(password,salt,{m:65536,t:3,p:1,dkLen:32}));
const after=await measure(()=>verifyPassword(vector.encoded,vector.password));
console.log(JSON.stringify({javascript_median_ms:before,wasm_median_ms:after,speedup:Number((before/after).toFixed(1)),parameters:'Argon2id v19 m=65536 t=3 p=1'},null,2));
