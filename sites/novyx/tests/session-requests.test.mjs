import test from 'node:test';
import assert from 'node:assert/strict';
import { createSessionRequests } from '../web/assets/session-requests.js';

const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};};
const expired=()=>Object.assign(new Error('expired'),{code:'expired',status:401});
const invalid=()=>Object.assign(new Error('invalid token'),{code:'invalid_token',status:401});
const tick=async()=>{await Promise.resolve();await Promise.resolve();};
function fixture(overrides={}) {
  const state={epoch:1,access:'original',expiry:1000},events={refreshes:0,fatal:[],writes:0};
  const client=createSessionRequests({session:()=>state,now:()=>0,
    refresh:async epoch=>{events.refreshes++;await overrides.refresh?.(epoch);state.access='new-token';state.expiry=1000;},
    send:overrides.send|| (async()=>({success:true})),
    changed:()=>events.writes++,fatal:error=>{events.fatal.push(error);state.epoch++;state.access='';}});
  return {client,state,events};
}

test('page reads do not wait behind a slow upload and writes remain ordered',async()=>{
  const slow=deferred(),order=[];
  const {client,events}=fixture({send:async(path)=>{order.push(path);if(path==='/upload')await slow.promise;return path;}});
  const upload=client.request('/upload','POST'),second=client.request('/edit','PUT');
  await tick();
  assert.equal(await client.request('/users'),'/users');
  assert.deepEqual(order,['/upload','/users']);
  slow.resolve();await Promise.all([upload,second]);
  assert.deepEqual(order,['/upload','/users','/edit']);assert.equal(events.writes,2);
});

test('concurrent reads share exactly one refresh-token rotation',async()=>{
  const gate=deferred(),tokens=[];
  const {client,state,events}=fixture({refresh:()=>gate.promise,send:async(_p,_m,_b,token)=>{tokens.push(token);return true;}});
  state.expiry=0;
  const first=client.request('/users'),second=client.request('/licenses');await tick();
  assert.equal(events.refreshes,1);
  gate.resolve();await Promise.all([first,second]);
  assert.deepEqual(tokens,['new-token','new-token']);assert.equal(events.fatal.length,0);
});

test('an old access-token rejection retries with tokens refreshed by another read',async()=>{
  const old=deferred(),calls=[];
  const {client,state,events}=fixture({send:async(path,_m,_b,token)=>{
    calls.push([path,token]);if(path==='/users'&&token==='original')return old.promise;return path;
  }});
  const first=client.request('/users');state.expiry=0;
  await client.request('/licenses');old.reject(invalid());
  assert.equal(await first,'/users');assert.equal(events.refreshes,1);assert.equal(events.fatal.length,0);
  assert.deepEqual(calls.at(-1),['/users','new-token']);
});

test('an access-token rejection during rotation waits for that same rotation',async()=>{
  const old=deferred(),rotation=deferred();
  const {client,state,events}=fixture({refresh:()=>rotation.promise,
    send:async(path,_m,_b,token)=>path==='/users'&&token==='original'?old.promise:path});
  const first=client.request('/users');state.expiry=0;
  const second=client.request('/licenses');await tick();old.reject(invalid());await tick();
  rotation.resolve();await Promise.all([first,second]);
  assert.equal(events.refreshes,1);assert.equal(events.fatal.length,0);
});

test('intentional page cancellation does not sign out or cancel another read',async()=>{
  const {client,events,state}=fixture({send:(path,_m,_b,_t,_binary,signal)=>{
    if(path==='/licenses')return Promise.resolve(path);
    return new Promise((_resolve,reject)=>signal.addEventListener('abort',()=>reject(new DOMException('cancelled','AbortError')),{once:true}));
  }});
  const controller=new AbortController(),first=client.request('/users','GET',undefined,false,{signal:controller.signal});
  controller.abort();await assert.rejects(first,{name:'AbortError'});
  assert.equal(await client.request('/licenses'),'/licenses');assert.equal(events.fatal.length,0);assert.equal(state.access,'original');
});

test('reset drops queued work from an old sign-in without blocking a new session',async()=>{
  const gate=deferred(),calls=[];
  const {client,state,events}=fixture({send:async path=>{calls.push(path);if(path==='/old')await gate.promise;return true;}});
  const old=client.request('/old','POST'),queued=client.request('/queued','POST');
  const results=Promise.allSettled([old,queued]);await tick();
  state.epoch++;state.access='other-session';client.reset();
  await client.request('/new','POST');gate.resolve();await results;
  assert.deepEqual(calls,['/old','/new']);assert.equal(events.fatal.length,0);assert.equal(events.writes,1);
});

test('genuine invalid-token errors fail closed and failed writes release the queue',async()=>{
  const {client,events}=fixture({send:async()=>{throw invalid();}});
  await assert.rejects(client.request('/users'),{code:'invalid_token'});
  assert.equal(events.refreshes,0);assert.equal(events.fatal.length,1);
  const order=[],other=fixture({send:async path=>{order.push(path);if(path==='/bad')throw Object.assign(new Error('bad input'),{status:422});return true;}});
  await assert.rejects(other.client.request('/bad','POST'));
  assert(await other.client.request('/good','POST'));assert.deepEqual(order,['/bad','/good']);
});

test('failed refresh is not replayed and cannot revive a session that signed out',async()=>{
  const gate=deferred(),first=fixture({refresh:()=>gate.promise});first.state.expiry=0;
  const pending=Promise.allSettled([first.client.request('/users'),first.client.request('/licenses')]);
  await tick();gate.reject(Object.assign(new Error('offline'),{code:'network_failure'}));
  assert((await pending).every(result=>result.status==='rejected'));
  assert.equal(first.events.refreshes,1);assert.equal(first.events.fatal.length,1);
});

test('email delivery errors keep the authenticated session and release queued writes',async()=>{
  const {client,events}=fixture({send:async path=>{
    if(path==='/email')throw Object.assign(new Error('delivery unavailable'),{code:'email_delivery_failed',status:503});
    return true;
  }});
  await assert.rejects(client.request('/email','POST'),{code:'email_delivery_failed'});
  assert(await client.request('/account'));assert.equal(events.fatal.length,0);
});
