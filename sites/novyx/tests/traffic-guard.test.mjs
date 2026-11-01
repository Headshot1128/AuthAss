import test from 'node:test';
import assert from 'node:assert/strict';
import { trafficGuard } from '../lib/traffic-guard.ts';
const request=(path='/',options={})=>new Request('https://test.invalid'+path,{...options,headers:{'cf-connecting-ip':'192.0.2.1',...options.headers}});
test('native flood rejection happens without invoking authentication limiter',async()=>{
  const result=await trafficGuard(request('/v1/admin/login'),{TRAFFIC_LIMITER:{async limit({key}){assert.equal(key,'ip:192.0.2.1');return {success:false};}},AUTH_LIMITER:{limit(){throw Error('must not run');}}});
  assert.equal(result.status,429);assert.equal(result.headers.get('retry-after'),'60');
});
test('auth limits cannot be bypassed by changing application or username',async()=>{
  const keys=[];
  const env={TRAFFIC_LIMITER:{async limit(){return {success:true};}},AUTH_LIMITER:{async limit({key}){keys.push(key);return {success:false};}}};
  for(const path of ['/v1/admin/login?application_id=a','/v1/login?application_id=b','/v1/auth/password/forgot'])assert.equal((await trafficGuard(request(path),env)).status,429);
  assert.equal(new Set(keys).size,1);
});
test('body preflight preserves binary uploads and rejects oversized JSON',async()=>{
  const env={TRAFFIC_LIMITER:{async limit(){return {success:true};}}};
  assert.equal((await trafficGuard(request('/v1/admin/login',{method:'POST',headers:{'content-length':'40000'}}),env)).status,413);
  for(const [path,method] of [['/v1/admin/files','POST'],['/v1/admin/storage/example','PUT']])assert.equal(await trafficGuard(request(path,{method,headers:{'content-length':'1000000'}}),env),null);
});
test('fallback limits floods and ignores spoofed forwarded headers',async()=>{
  const req=()=>request('/',{headers:{'cf-connecting-ip':'192.0.2.99','x-forwarded-for':crypto.randomUUID()}});
  for(let i=0;i<300;i++)assert.equal(await trafficGuard(req(),{}),null);
  assert.equal((await trafficGuard(req(),{})).status,429);
  assert.equal((await trafficGuard(new Request('https://test.invalid/'),{})).status,400);
});
