import { argon2id } from '../vendor/hash-wasm/lib/argon2.ts';
import { clearArgon2Memory } from '../vendor/hash-wasm/lib/WASMInterface.ts';
const encoder = new TextEncoder();
export const bytes = (s:string) => encoder.encode(s);
export function b64(a:Uint8Array) { let s=''; for(const c of a) s+=String.fromCharCode(c); return btoa(s); }
export const un64=(s:string)=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
export function random(n=32) { return b64(crypto.getRandomValues(new Uint8Array(n))).replaceAll('+','-').replaceAll('/','_').replaceAll('=',''); }
export async function digest(s:string) { return [...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes(s)))].map(c=>c.toString(16).padStart(2,'0')).join(''); }
export function equal(a:Uint8Array,b:Uint8Array) { let d=a.length^b.length; for(let i=0;i<a.length;i++) d|=a[i]^(b[i]??0); return d===0; }
let kdfQueue:Promise<void>=Promise.resolve(),pending=0;
async function passwordMemory<T>(operation:()=>Promise<T>):Promise<T> {
  if(pending>=4)throw Error('Password service busy');
  pending++;const previous=kdfQueue;let release!:()=>void;kdfQueue=new Promise(resolve=>{release=resolve;});
  await previous;try{return await operation();}finally{pending--;release();}
}
export async function hashPassword(password:string) {
  return passwordMemory(async()=>{
  const salt=crypto.getRandomValues(new Uint8Array(16));
  const hash=await passwordHash(password,salt);
  return `$argon2id$v=19$m=65536,t=3,p=1$${b64(salt).replaceAll('=','')}$${b64(hash).replaceAll('=','')}`;
  });
}
export async function verifyPassword(encoded:string,password:string) {
  return passwordMemory(async()=>{
  try {
    const match=/^\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$([^$]+)\$([^$]+)$/.exec(encoded);
    if(!match) return false;
    const [,m,t,p,salt,expected]=match;
    if(+m!==65536||+t!==3||+p!==1) return false;
    const result=await passwordHash(password,un64(salt));
    return equal(result,un64(expected));
  } catch { return false; }
  });
}
async function passwordHash(password:string,salt:Uint8Array):Promise<Uint8Array> {
  try {
    return await argon2id({password:bytes(password),salt,iterations:3,parallelism:1,
      memorySize:65536,hashLength:32,outputType:'binary'});
  } finally { await clearArgon2Memory(); }
}
async function displayKey(secret:string) {
  if(!secret) throw Error('Missing display encryption key');
  return crypto.subtle.importKey('raw',un64(secret),{name:'AES-GCM'},false,['encrypt','decrypt']);
}
export async function encryptKey(value:string,secret:string) {
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const encrypted=await crypto.subtle.encrypt({name:'AES-GCM',iv},await displayKey(secret),bytes(value));
  return `aesgcm:${b64(iv)}:${b64(new Uint8Array(encrypted))}`;
}
export async function decryptKey(value:string,secret:string) {
  const [type,iv,cipher]=value.split(':');
  if(type!=='aesgcm') throw Error('Unsupported key encoding');
  return new TextDecoder().decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:un64(iv)},await displayKey(secret),un64(cipher)));
}
export function licenseKey() {
  const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'; let out='';
  while(out.length<12) { for(const n of crypto.getRandomValues(new Uint8Array(24))) { if(n<252) out+=alphabet[n%36]; if(out.length===12) break; } }
  return `NOVYX-${out.slice(0,6)}-${out.slice(6)}`;
}
