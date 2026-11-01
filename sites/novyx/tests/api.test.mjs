import test from 'node:test';
import './wasm-setup.mjs';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync, readdirSync } from 'node:fs';
import { api } from '../lib/novyx-api.ts';
import { hashPassword, b64, digest, random, licenseKey } from '../lib/novyx-crypto.ts';

class Database {
  constructor(){this.db=new DatabaseSync(':memory:');for(const f of readdirSync('drizzle').filter(f=>f.endsWith('.sql')))this.db.exec(readFileSync('drizzle/'+f,'utf8'));}
  withSession(){return this;}
  prepare(sql){const db=this.db;return {bind(...values){return {async first(){return db.prepare(sql).get(...values)||null;},async all(){return {results:db.prepare(sql).all(...values)};},async run(){const result=db.prepare(sql).run(...values);return {meta:{changes:Number(result.changes)}};}};}};}
  async batch(statements){this.db.exec('BEGIN');try{const result=[];for(const s of statements)result.push(await s.run());this.db.exec('COMMIT');return result;}catch(e){this.db.exec('ROLLBACK');throw e;}}
}
class Bucket {
  files=new Map();
  async put(name,value){this.files.set(name,new Uint8Array(value));}
  async delete(name){this.files.delete(name);}
  async head(name){const bytes=this.files.get(name);return bytes?{size:bytes.length}:null;}
  async get(name){const bytes=this.files.get(name);return bytes?{size:bytes.length,body:new ReadableStream({start(c){c.enqueue(bytes);c.close();}})}:null;}
}

test('freeze pauses key and account clocks, blocks activation and resumes remaining time',async()=>{
  const DB=new Database(),now=Math.floor(Date.now()/1000),password='freeze regression password';
  const env={DB,BUCKET:new Bucket(),OWNER_USERNAME:'freeze-owner',LICENSE_DISPLAY_KEY:b64(crypto.getRandomValues(new Uint8Array(32)))};
  const owner=crypto.randomUUID(),customer=crypto.randomUUID(),key=crypto.randomUUID(),value=licenseKey();
  const hash=await hashPassword(password);
  DB.db.prepare("INSERT INTO users(id,username,password_hash,role,console_only,web_approved,created_at) VALUES(?,?,?,'admin',1,1,?)").run(owner,'freeze-owner',hash,now);
  DB.db.prepare('INSERT INTO users(id,username,password_hash,subscription_until,created_at) VALUES(?,?,?,?,?)').run(customer,'freeze-customer',hash,now+86400,now);
  DB.db.prepare("INSERT INTO licenses(id,key_hash,expires_at,permission,user_id) VALUES(?,?,?,'premium',?)").run(key,await digest(value),now+86400,customer);
  const call=(path,token='',body)=>api(new Request('https://test.invalid'+path,{method:'POST',headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},body:body===undefined?undefined:JSON.stringify(body)}),env);
  const token=(await(await call('/v1/admin/login','',{username:'freeze-owner',password})).json()).access_token;
  assert(token);
  assert.equal((await call('/v1/admin/licenses/'+key+'/freeze')).status,401);
  assert.equal((await(await call('/v1/admin/licenses/'+key+'/freeze',token)).json()).frozen,true);
  assert(DB.db.prepare('SELECT frozen_at FROM users WHERE id=?').get(customer).frozen_at);
  DB.db.prepare('UPDATE licenses SET frozen_at=? WHERE id=?').run(now-3600,key);
  DB.db.prepare('UPDATE users SET frozen_at=? WHERE id=?').run(now-3600,customer);
  assert.equal((await(await call('/v1/admin/licenses/'+key+'/freeze',token)).json()).frozen,false);
  const license=DB.db.prepare('SELECT * FROM licenses WHERE id=?').get(key),user=DB.db.prepare('SELECT * FROM users WHERE id=?').get(customer);
  assert.equal(license.frozen_at,null);assert.equal(user.frozen_at,null);
  assert(license.expires_at>=now+90000&&license.expires_at<=now+90010);
  assert(user.subscription_until>=now+90000&&user.subscription_until<=now+90010);
});

test('approved website users manage existing application customers without account creation or website privileges',async()=>{
  const DB=new Database(),password='customer management test password',hash=await hashPassword(password),now=Math.floor(Date.now()/1000);
  const env={DB,BUCKET:new Bucket(),OWNER_USERNAME:'gerry2.0',LICENSE_DISPLAY_KEY:b64(crypto.getRandomValues(new Uint8Array(32)))};
  const ownerId=crypto.randomUUID(),memberId=crypto.randomUUID();
  for(const [id,username] of [[ownerId,'gerry2.0'],[memberId,'staff']])DB.db.prepare("INSERT INTO users(id,username,password_hash,role,console_only,web_approved,created_at) VALUES(?,?,?,'admin',1,1,?)").run(id,username,hash,now);
  const defaultApp='00000000-0000-4000-8000-000000000001';
  const call=(path,method='GET',body,token='',app=defaultApp)=>api(new Request('https://test.invalid'+path,{method,headers:{'Content-Type':'application/json','x-application-id':app,...(token?{Authorization:'Bearer '+token}:{})},body:body===undefined?undefined:JSON.stringify(body)}),env);
  const owner=await (await call('/v1/admin/login','POST',{username:'gerry2.0',password})).json();
  const staff=await (await call('/v1/admin/login','POST',{username:'staff',password})).json();assert(staff.access_token);
  const app=(await (await call('/v1/admin/applications','POST',{name:'Other app'},owner.access_token)).json()).id;
  const customer=(await (await call('/v1/admin/users','POST',{username:'registered-customer',password,account_type:'application'},owner.access_token)).json()).id;
  const grant={status:'active',subscription_until:now+3600};
  const lookup=await (await call('/v1/admin/users/lookup?username=registered-customer','GET',undefined,staff.access_token)).json();assert.equal(lookup.user.id,customer);
  assert.equal((await call('/v1/admin/users/'+customer,'PUT',grant,staff.access_token)).status,200);
  for(const operation of ['reset-hwid','ban','unban'])assert.equal((await call('/v1/admin/users/'+customer+'/'+operation,'POST',{},staff.access_token)).status,200);
  assert.equal((await call('/v1/admin/users/'+customer,'PUT',{...grant,web_access:true},staff.access_token)).status,422);
  assert.equal((await call('/v1/admin/users/'+customer,'PUT',grant,staff.access_token,app)).status,403);
  assert.equal((await call('/v1/admin/users/'+customer,'DELETE',undefined,staff.access_token,app)).status,403);
  for(const operation of ['reset-hwid','ban','unban'])assert.equal((await call('/v1/admin/users/'+customer+'/'+operation,'POST',{},staff.access_token,app)).status,403);
  for(const target of [ownerId,memberId]){
    assert.equal((await call('/v1/admin/users/'+target,'PUT',grant,staff.access_token)).status,403);
    assert.equal((await call('/v1/admin/users/'+target,'DELETE',undefined,staff.access_token)).status,403);
    assert.equal((await call('/v1/admin/users/'+target+'/ban','POST',{},staff.access_token)).status,403);
  }
  for(const account_type of ['website','application'])assert.equal((await call('/v1/admin/users','POST',{username:'blocked-create',password,account_type},staff.access_token)).status,403);
  assert.equal((await call('/v1/admin/users?scope=website','GET',undefined,staff.access_token)).status,403);
  assert.equal((await call('/v1/admin/users/'+customer+'/permissions','PUT',{permission:'admin',allowed:true},staff.access_token)).status,403);
  const created=await call('/v1/admin/applications','POST',{name:'Staff application'},staff.access_token);assert.equal(created.status,201);
  const staffApp=(await created.json()).id;assert.match(staffApp,/^[0-9a-f-]{36}$/);
  assert.equal((await call('/v1/admin/applications/'+staffApp,'PUT',{name:'Renamed application',status:'disabled'},staff.access_token)).status,200);
  assert.equal(DB.db.prepare('SELECT status FROM applications WHERE id=?').get(staffApp).status,'disabled');
  assert(DB.db.prepare("SELECT 1 FROM audit_logs WHERE actor_id=? AND event='admin.application.create'").get(memberId));
  assert.equal((await call('/v1/admin/applications','POST',{name:'Anonymous application'})).status,401);
  const sdk=await (await call('/v1/login','POST',{username:'registered-customer',password,hardware_id:'customer-device-test'})).json();assert(sdk.access_token);
  assert.equal((await call('/v1/admin/users/'+customer+'/ban','POST',{},sdk.access_token)).status,403);
  assert.equal((await call('/v1/admin/applications','POST',{name:'SDK application'},sdk.access_token)).status,403);
  assert.equal((await call('/v1/admin/applications/'+staffApp,'PUT',{name:'SDK update',status:'active'},sdk.access_token)).status,403);
  assert.equal((await call('/v1/admin/users/'+customer,'DELETE',undefined,staff.access_token)).status,200);
  assert(!DB.db.prepare('SELECT 1 FROM users WHERE id=?').get(customer));
  assert(DB.db.prepare("SELECT 1 FROM audit_logs WHERE actor_id=? AND event='admin.user.delete'").get(memberId));
  DB.db.prepare('UPDATE users SET web_approved=0 WHERE id=?').run(memberId);
  assert.equal((await call('/v1/admin/applications','POST',{name:'Unapproved application'},staff.access_token)).status,401);
  assert.equal((await call('/v1/admin/applications/'+staffApp,'PUT',{name:'Unapproved update',status:'active'},staff.access_token)).status,401);
  assert.equal((await call('/v1/admin/users','GET',undefined,staff.access_token)).status,401);
  DB.db.close();
});

test('stay signed in is opt-in, uses a private cookie and respects logout, expiry and revocation',async()=>{
  const DB=new Database(),password='remember test password',userId=crypto.randomUUID();
  const env={DB,BUCKET:new Bucket(),OWNER_USERNAME:'gerry2.0',LICENSE_DISPLAY_KEY:b64(crypto.getRandomValues(new Uint8Array(32)))};
  DB.db.prepare("INSERT INTO users(id,username,password_hash,role,console_only,created_at) VALUES(?,?,?,'admin',1,?)").run(userId,'gerry2.0',await hashPassword(password),Math.floor(Date.now()/1000));
  const call=(path,body={},headers={})=>api(new Request('https://test.invalid'+path,{method:'POST',headers:{'Content-Type':'application/json',Origin:'https://test.invalid',...headers},body:JSON.stringify(body)}),env);
  const login=remember=>call('/v1/admin/login',{username:'gerry2.0',password,remember});
  const plain=await login(false);assert.match(plain.headers.get('Set-Cookie'),/Max-Age=0/);
  const response=await login(true),data=await response.json(),setCookie=response.headers.get('Set-Cookie');
  for(const flag of ['__Host-novyx-remember=','Secure','HttpOnly','SameSite=Strict','Path=/'])assert(setCookie.includes(flag));
  assert.match(setCookie,/Max-Age=2592000/);
  const cookie=setCookie.split(';')[0],secret=cookie.split('=')[1];
  assert(!JSON.stringify(data).includes(secret));
  assert.equal((await call('/v1/admin/resume',{}, {Cookie:cookie,Origin:'https://attacker.invalid'})).status,403);
  assert.equal((await call('/v1/admin/resume')).status,401);
  const restored=await (await call('/v1/admin/resume',{}, {Cookie:cookie})).json();assert.equal(restored.user.is_owner,true);assert(restored.access_token);
  assert.equal((await call('/v1/admin/resume',{}, {Cookie:cookie})).status,200); // Concurrent tabs retain the same browser session.
  const logout=await call('/v1/admin/logout',{}, {Authorization:'Bearer '+restored.access_token});assert.equal(logout.status,200);assert.match(logout.headers.get('Set-Cookie'),/Max-Age=0/);
  const revoked=await call('/v1/admin/resume',{}, {Cookie:cookie});assert.equal(revoked.status,401);assert.match(revoked.headers.get('Set-Cookie'),/Max-Age=0/);
  const next=await login(true),nextCookie=next.headers.get('Set-Cookie').split(';')[0];
  DB.db.prepare('UPDATE sessions SET expires_at=0 WHERE user_id=?').run(userId);
  assert.equal((await call('/v1/admin/resume',{}, {Cookie:nextCookie})).status,401);
  DB.db.close();
});

test('verified email recovery covers owner and website users, isolates SDK users and consumes reset links atomically',async()=>{
  const DB=new Database(),password='original test password',replacement='replacement test password';
  const env={DB,BUCKET:new Bucket(),OWNER_USERNAME:'gerry2.0',LICENSE_DISPLAY_KEY:b64(crypto.getRandomValues(new Uint8Array(32)))};
  const hash=await hashPassword(password),now=Math.floor(Date.now()/1000);
  for(const [username,role,consoleOnly,approved] of [['gerry2.0','admin',1,0],['member','admin',1,1],['sdk-user','user',0,0],['pending','admin',1,0]])
    DB.db.prepare('INSERT INTO users(id,username,password_hash,role,console_only,web_approved,created_at) VALUES(?,?,?,?,?,?,?)').run(crypto.randomUUID(),username,hash,role,consoleOnly,approved,now);
  let ip=0;
  const call=(path,body,token='',method='POST')=>api(new Request('https://untrusted.invalid'+path,{method,headers:{'Content-Type':'application/json','cf-connecting-ip':'test-'+(++ip),...(token?{Authorization:'Bearer '+token}:{})},body:body===undefined?undefined:JSON.stringify(body)}),env);
  const login=async(username,pw=password)=>(await call('/v1/admin/login',{username,password:pw})).json();
  const messages=[],originalFetch=globalThis.fetch;
  let failDelivery=false;
  globalThis.fetch=async(url,options)=>{assert.equal(url,'https://api.resend.com/emails');assert.equal(options.redirect,'manual','Cloudflare Workers must reject redirects without using unsupported error mode');assert.equal(options.headers.Authorization,'Bearer test-only-key');if(failDelivery)return new Response('{}',{status:503});messages.push(JSON.parse(options.body));return Response.json({id:'test-message'});};
  const link=()=>new URL(messages.at(-1).text.match(/https:\/\/[^\s]+/)[0]);
  const token=()=>new URLSearchParams(link().hash.slice(1)).get('token');
  try {
    const owner=await login('gerry2.0'),member=await login('member');
    assert.equal((await call('/v1/auth/password/forgot',{email:'owner@example.test'})).status,503);
    env.RESEND_API_KEY='test-only-key';env.EMAIL_FROM='NOVYX <accounts@example.test>';env.PUBLIC_SITE_URL='https://novyx.example.test';
    assert.equal((await call('/v1/admin/account/email',{email:'owner@example.test',password:'wrong password'},owner.access_token)).status,401);
    assert.equal(messages.length,0);
    for(const [username,email,session] of [['gerry2.0','owner@example.test',owner],['member','member@example.test',member]]){
      assert.equal((await call('/v1/admin/account/email',{email,password},session.access_token)).status,200);
      assert.equal(link().origin,'https://novyx.example.test');assert.equal(link().search,'');
      const verifyToken=token();assert.equal(verifyToken.length,64);
      assert(!JSON.stringify(DB.db.prepare('SELECT * FROM email_tokens').all()).includes(verifyToken));
      const unverified=await (await call('/v1/auth/password/forgot',{email})).json();assert(unverified.success);
      assert.equal((await call('/v1/auth/email/verify',{token:verifyToken})).status,200);
      assert.equal((await call('/v1/auth/email/verify',{token:verifyToken})).status,422);
      const profile=await (await call('/v1/admin/account',undefined,session.access_token,'GET')).json();assert.equal(profile.email,email);assert.equal(profile.email_verified,true);
      const unknown=await (await call('/v1/auth/password/forgot',{email:'unknown@example.test'})).json();
      const count=messages.length;
      assert.deepEqual(await (await call('/v1/auth/password/forgot',{email})).json(),unknown);assert.equal(messages.length,count+1);
      const resetToken=token();
      assert.equal((await call('/v1/auth/email/verify',{token:resetToken})).status,422);
      assert.equal((await call('/v1/auth/password/reset',{token:resetToken,password:'short'})).status,422);
      if(username==='member'){
        DB.db.prepare('UPDATE email_tokens SET expires_at=? WHERE hash=?').run(now-1,await digest(resetToken));
        assert.equal((await call('/v1/auth/password/reset',{token:resetToken,password:replacement})).status,422);
        await call('/v1/auth/password/forgot',{email});
      }
      const usable=token();
      const results=await Promise.all([call('/v1/auth/password/reset',{token:usable,password:replacement}),call('/v1/auth/password/reset',{token:usable,password:replacement})]);
      assert.deepEqual(results.map(r=>r.status).sort(),[200,422]);
      assert.equal((await call('/v1/admin/account',undefined,session.access_token,'GET')).status,401);
      assert((await login(username,replacement)).access_token);assert(!(await login(username)).access_token);
      assert.equal((await call('/v1/auth/password/reset',{token:usable,password:replacement})).status,422);
    }
    const sdk=await (await call('/v1/login',{username:'sdk-user',password,hardware_id:'test-hardware-device'})).json();assert(sdk.access_token);
    assert.equal((await call('/v1/admin/account/email',{email:'sdk@example.test',password},sdk.access_token)).status,403);
    DB.db.prepare("UPDATE users SET email='sdk@example.test',email_verified_at=? WHERE username IN ('sdk-user','pending')").run(now);
    const count=messages.length;await call('/v1/auth/password/forgot',{email:'sdk@example.test'});assert.equal(messages.length,count);
    failDelivery=true;
    assert.equal((await call('/v1/auth/password/forgot',{email:'owner@example.test'})).status,200);
    assert.equal(DB.db.prepare("SELECT COUNT(*) n FROM email_tokens WHERE purpose='reset-password' AND used=0").get().n,0);
    const logs=JSON.stringify(DB.db.prepare('SELECT * FROM audit_logs').all());assert(!logs.includes(replacement));assert(!logs.includes('owner@example.test'));
  } finally {globalThis.fetch=originalFetch;DB.db.close();}
});

test('one-time owner recovery resets only the owner, revokes sessions and rolls back on failure',async()=>{
  const DB=new Database(),ownerId=crypto.randomUUID(),otherId=crypto.randomUUID(),secret=random(48);
  const original='original owner password',replacement='new test-only owner password';
  const hash=await hashPassword(original),now=Math.floor(Date.now()/1000);
  const env={DB,BUCKET:new Bucket(),OWNER_USERNAME:'gerry2.0',LICENSE_DISPLAY_KEY:b64(crypto.getRandomValues(new Uint8Array(32)))};
  for(const [id,username] of [[ownerId,'gerry2.0'],[otherId,'another-admin']])
    DB.db.prepare("INSERT INTO users(id,username,password_hash,role,console_only,created_at) VALUES(?,?,?,'admin',1,?)").run(id,username,hash,now);
  const call=(path,method='GET',body,headers={})=>api(new Request('https://test.invalid'+path,{
    method,headers:{'Content-Type':'application/json',...headers},body:body===undefined?undefined:JSON.stringify(body)}),env);
  const login=password=>call('/v1/admin/login','POST',{username:'gerry2.0',password});
  const owner=await (await login(original)).json();assert(owner.access_token);
  const target={username:'gerry2.0',user_id:ownerId,password:replacement};
  const reset=(body=target,token=secret)=>call('/_maintenance/owner-password','POST',body,{'x-owner-recovery-token':token});
  assert.equal((await reset()).status,403); // Disabled by default.
  env.OWNER_RECOVERY_TOKEN=secret;env.OWNER_RECOVERY_DEADLINE=String(now+900);
  assert.equal((await reset(target,'wrong-token-that-is-at-least-32-characters')).status,403);
  env.OWNER_RECOVERY_DEADLINE=String(now-1);assert.equal((await reset()).status,403);
  env.OWNER_RECOVERY_DEADLINE=String(now+7200);assert.equal((await reset()).status,403);
  env.OWNER_RECOVERY_DEADLINE=String(now+900);
  assert.equal((await reset({...target,username:'another-admin',user_id:otherId})).status,403);
  assert.equal((await reset({...target,user_id:otherId})).status,403);
  assert.equal((await reset({...target,password:'short'})).status,422);
  DB.db.exec("CREATE TRIGGER fail_recovery BEFORE INSERT ON audit_logs WHEN NEW.event='maintenance.owner.password_reset' BEGIN SELECT RAISE(ABORT,'test rollback'); END");
  assert.equal((await reset()).status,500);
  assert.equal(DB.db.prepare('SELECT password_hash FROM users WHERE id=?').get(ownerId).password_hash,hash);
  assert.equal((await call('/v1/admin/session','GET',undefined,{Authorization:'Bearer '+owner.access_token})).status,200);
  DB.db.exec('DROP TRIGGER fail_recovery');
  assert.equal((await reset()).status,200);
  assert.equal((await call('/v1/admin/session','GET',undefined,{Authorization:'Bearer '+owner.access_token})).status,401);
  assert.equal((await login(original)).status,401);
  const fresh=await (await login(replacement)).json();assert(fresh.access_token);
  assert.equal((await reset()).status,409);
  assert.equal((await call('/v1/admin/session','GET',undefined,{Authorization:'Bearer '+fresh.access_token})).status,200);
  assert.equal(DB.db.prepare('SELECT password_hash FROM users WHERE id=?').get(otherId).password_hash,hash);
  assert.equal(DB.db.prepare("SELECT COUNT(*) n FROM audit_logs WHERE event='maintenance.owner.password_reset'").get().n,1);
  const logs=JSON.stringify(DB.db.prepare('SELECT * FROM audit_logs').all());
  assert(!logs.includes(replacement));assert(!logs.includes(secret));
  delete env.OWNER_RECOVERY_TOKEN;delete env.OWNER_RECOVERY_DEADLINE;
  assert.equal((await reset()).status,403);
  DB.db.close();
});
test('hosted migration preserves authorization, owner approval, licenses, private files, rotation and deletion',async()=>{
  const DB=new Database(),env={DB,BUCKET:new Bucket(),OWNER_USERNAME:'gerry2.0',LICENSE_DISPLAY_KEY:b64(crypto.getRandomValues(new Uint8Array(32))),MIGRATION_TOKEN:random()};
  const password='correct horse battery staple',hash=await hashPassword(password),now=Math.floor(Date.now()/1000);
  const user=(id,role)=>({id,username:id,password_hash:hash,status:'active',role,subscription_until:now+3600,password_until:null,created_at:now,console_only:role==='admin'?1:0,web_approved:0});
  const snapshot={users:[user('gerry2.0','admin'),user('application','user')],licenses:[],permissions:[],variables:[],files:[],audit_logs:[]};
  async function call(path,method='GET',body,token='',extra={}){return api(new Request('https://test.invalid'+path,{method,headers:{...(body!==undefined?{'Content-Type':'application/json'}:{}),...(token?{Authorization:'Bearer '+token}:{}),...extra},body:body===undefined?undefined:JSON.stringify(body)}),env);}
  assert.equal((await call('/_migration/import','POST',snapshot)).status,403);
  assert.equal((await call('/_migration/import','POST',snapshot,'',{'x-migration-token':env.MIGRATION_TOKEN})).status,200);
  assert.equal((await call('/_migration/import','POST',snapshot,'',{'x-migration-token':env.MIGRATION_TOKEN})).status,409);
  const credentials={username:'gerry2.0',password};
  assert.equal((await call('/v1/admin/login','POST',{...credentials,password:'incorrect password'})).status,401);
  assert.equal((await call('/v1/admin/login','POST',{username:'unknown',password})).status,401);
  const owner=await (await call('/v1/admin/login','POST',credentials)).json();assert.equal(owner.success,true);
  assert.deepEqual(owner.user,{username:'gerry2.0',user_id:'gerry2.0',is_owner:true,role:'admin'});
  assert.equal((await call('/v1/admin/session','GET',undefined,owner.access_token)).status,200);
  const pending=await (await call('/v1/admin/users','POST',{username:'member',password},owner.access_token)).json();assert(pending.id);
  assert.equal((await call('/v1/admin/login','POST',{username:'member',password})).status,403);
  const grant={status:'active',subscription_until:0,web_access:true};
  assert.equal((await call('/v1/admin/users/'+pending.id,'PUT',grant,owner.access_token)).status,200);
  const member=await (await call('/v1/admin/login','POST',{username:'member',password})).json();assert(member.access_token);
  assert.equal((await call('/v1/admin/bootstrapper')).status,401);
  const bootstrap=await (await call('/v1/admin/bootstrapper','GET',undefined,member.access_token)).json();
  assert.equal(bootstrap.sdk_version,1);assert.equal(bootstrap.max_bytes,67108864);
  assert.match(bootstrap.template_sha256,/^[a-f0-9]{64}$/);
  assert.equal(bootstrap.template_url,'/v1/admin/bootstrapper/template');
  const assetBytes=new Uint8Array([77,90,0,255]);
  env.ASSETS={async fetch(request){assert.match(request.url,/\/bootstrap\/novyx-(template\.bin|bootstrap-sdk\.zip)$/);return new Response(assetBytes);}};
  assert.equal((await call('/v1/admin/bootstrapper/template')).status,401);
  assert.deepEqual(new Uint8Array(await (await call(bootstrap.template_url,'GET',undefined,member.access_token)).arrayBuffer()),assetBytes);
  assert.equal((await call(bootstrap.sdk_url,'GET',undefined,owner.access_token)).headers.get('Content-Type'),'application/vnd.novyx.asset');
  const packageBody={size:1024,sha256:'a'.repeat(64)};
  assert.equal((await call('/v1/admin/bootstrapper','POST',packageBody,member.access_token)).status,200);
  assert.equal((await call('/v1/admin/bootstrapper','POST',{...packageBody,size:67108865},owner.access_token)).status,422);
  assert.equal((await call('/v1/admin/bootstrapper','POST',{...packageBody,sha256:'bad'},owner.access_token)).status,422);
  assert.equal(DB.db.prepare("SELECT target FROM audit_logs WHERE event='admin.bootstrapper.package'").get().target,packageBody.sha256);
  const directory=await (await call('/v1/admin/users','GET',undefined,member.access_token)).json();
  assert.deepEqual(directory.users.map(user=>user.username),['application']);
  assert(!JSON.stringify(directory).includes('gerry2.0'));assert(!JSON.stringify(directory).includes('password_hash'));
  assert.equal((await call('/v1/admin/users?scope=website','GET',undefined,member.access_token)).status,403);
  const website=await (await call('/v1/admin/users?scope=website','GET',undefined,owner.access_token)).json();
  assert(website.users.some(user=>user.is_owner));assert(!website.users.some(user=>user.username==='application'));
  assert.equal((await call('/v1/admin/users/'+pending.id,'PUT',grant,member.access_token)).status,403);
  assert.equal((await call('/v1/admin/users','POST',{username:'forbidden-app',password,account_type:'application'},member.access_token)).status,403);
  assert.equal((await call('/v1/admin/users','POST',{username:'bad-type',password,account_type:'owner'},owner.access_token)).status,422);
  assert.equal((await call('/v1/admin/users','POST',{username:'short-website',password:'x',account_type:'website'},owner.access_token)).status,422);
  const provisioned=await (await call('/v1/admin/users','POST',{username:'sdk-member',password,account_type:'application'},owner.access_token)).json();
  assert(provisioned.id);assert.equal(provisioned.account_type,'application');
  const appRow=DB.db.prepare('SELECT * FROM users WHERE id=?').get(provisioned.id);
  assert.equal(appRow.console_only,0);assert.equal(appRow.role,'user');assert.equal(appRow.subscription_until,0);
  assert.equal((await call('/v1/admin/users','POST',{username:'sdk-member',password,account_type:'application'},owner.access_token)).status,409);
  assert.equal((await call('/v1/admin/login','POST',{username:'sdk-member',password})).status,401);
  assert.equal((await call('/v1/admin/users/'+provisioned.id,'PUT',grant,owner.access_token)).status,422);
  assert.equal(DB.db.prepare('SELECT role FROM users WHERE id=?').get(provisioned.id).role,'user');
  const application=await (await call('/v1/login','POST',{username:'sdk-member',password,hardware_id:'original-device-id'})).json();
  assert(application.access_token);
  assert.equal((await call('/v1/admin/bootstrapper','GET',undefined,application.access_token,{'x-hardware-id':'original-device-id'})).status,403);
  assert.equal((await call('/v1/admin/overview','GET',undefined,application.access_token,{'x-hardware-id':'original-device-id'})).status,403);
  const userHeaders={'x-hardware-id':'original-device-id'};
  assert.equal((await call('/v1/variables/premium','GET',undefined,application.access_token,userHeaders)).status,403);
  assert.equal((await call('/v1/admin/variables/flag','PUT',{name:'premium',value:'enabled',permission:'premium'},owner.access_token)).status,200);
  const license=await (await call('/v1/admin/licenses','POST',{days:1,hardware_bound:true},owner.access_token)).json();assert.match(license.key,/^NOVYX-[A-Z0-9]{6}-[A-Z0-9]{6}$/);
  assert.equal((await call('/v1/admin/licenses','POST',{days:1000},owner.access_token)).status,422);
  assert.equal((await call('/v1/licenses/activate','POST',{key:license.key},application.access_token,userHeaders)).status,200);
  const customers=await (await call('/v1/admin/users','GET',undefined,member.access_token)).json();
  assert.equal(customers.users.find(user=>user.id===provisioned.id).licenses[0].key,license.key);
  assert(!JSON.stringify(customers).includes('key_ciphertext'));
  assert.equal((await call('/v1/admin/users','GET',undefined,application.access_token,userHeaders)).status,403);
  assert.equal((await call('/v1/variables/premium','GET',undefined,application.access_token,userHeaders)).status,200);
  const upload=(token,content='uploaded bytes')=>api(new Request('https://test.invalid/v1/admin/files',{method:'POST',headers:{Authorization:'Bearer '+token},body:new TextEncoder().encode(content)}),env);
  assert.equal((await upload('')).status,401);
  assert.equal((await upload(member.access_token)).status,201);
  assert.equal((await upload(application.access_token)).status,403);
  assert.equal((await upload(owner.access_token,'')).status,422);
  const uploadedResponse=await upload(owner.access_token);assert.equal(uploadedResponse.status,201);
  const uploaded=await uploadedResponse.json();assert.match(uploaded.id,/^[a-f0-9-]{36}$/);
  const second=await (await upload(owner.access_token)).json();assert.notEqual(uploaded.id,second.id);
  assert.equal(await (await call('/v1/files/'+uploaded.id+'/content','GET',undefined,application.access_token,userHeaders)).text(),'uploaded bytes');
  DB.db.prepare('UPDATE files SET enabled=0 WHERE id=?').run(uploaded.id);
  assert.equal((await call('/v1/files/'+uploaded.id+'/content','GET',undefined,application.access_token,userHeaders)).status,403);
  assert.equal((await api(new Request('https://test.invalid/v1/admin/storage/payload.bin',{method:'PUT',headers:{Authorization:'Bearer '+owner.access_token},body:new TextEncoder().encode('private payload')}),env)).status,200);
  assert.equal((await call('/v1/admin/files/payload','PUT',{storage_name:'payload.bin',permission:'premium',enabled:true,max_bytes:1000},owner.access_token)).status,200);
  assert.equal(await (await call('/v1/files/payload/content','GET',undefined,application.access_token,userHeaders)).text(),'private payload');
  DB.db.prepare('UPDATE licenses SET expires_at=? WHERE id=?').run(now-1,license.id);
  assert.equal((await call('/v1/variables/premium','GET',undefined,application.access_token,userHeaders)).status,403);
  assert.equal((await call('/v1/files/payload/content','GET',undefined,application.access_token,userHeaders)).status,403);
  assert.equal((await call('/v1/licenses/activate','POST',{key:license.key},application.access_token,userHeaders)).status,403);
  assert.equal((await call('/v1/admin/licenses/'+license.id+'/extend','POST',{days:1},owner.access_token)).status,200);
  assert.equal((await call('/v1/variables/premium','GET',undefined,application.access_token,userHeaders)).status,200);
  assert.equal((await call('/v1/admin/licenses/'+license.id+'/reset-hwid','POST',{},owner.access_token)).status,200);
  assert.equal((await call('/v1/session','GET',undefined,application.access_token,userHeaders)).status,401);
  const old=member.refresh_token,newPair=await (await call('/v1/refresh','POST',{refresh_token:old})).json();assert(newPair.access_token);
  assert.equal((await call('/v1/refresh','POST',{refresh_token:old})).status,401);
  assert.equal((await call('/v1/admin/overview','GET',undefined,newPair.access_token)).status,401);
  assert.equal((await call('/v1/admin/users/'+pending.id,'DELETE',undefined,owner.access_token)).status,200);
  assert.equal((await call('/v1/admin/users/gerry2.0','DELETE',undefined,owner.access_token)).status,409);
  DB.db.prepare('UPDATE access_tokens SET expires_at=?').run(now-1);
  assert.equal((await call('/v1/admin/overview','GET',undefined,owner.access_token)).status,401);
  assert(!JSON.stringify(DB.db.prepare('SELECT * FROM audit_logs').all()).includes(license.key));
  DB.db.close();
});

test('license-backed registration works with public registration disabled and binds the computer',async()=>{
  const DB=new Database(),BUCKET=new Bucket(),env={DB,BUCKET,OWNER_USERNAME:'gerry2.0',REGISTRATION:'false',LICENSE_DISPLAY_KEY:b64(new Uint8Array(32))};
  const password='x',hardware='registration-original-device',now=Math.floor(Date.now()/1000);
  async function call(path,method='POST',body,token='',hw=hardware){return api(new Request('https://test.invalid'+path,{method,headers:{'Content-Type':'application/json','x-hardware-id':hw,'cf-connecting-ip':random(),...(token?{Authorization:'Bearer '+token}:{})},body:body===undefined?undefined:JSON.stringify(body)}),env);}
  async function key(extra={}){const value=licenseKey(),identifier=random();DB.db.prepare('INSERT INTO licenses(id,key_hash,expires_at,permission,revoked,user_id) VALUES(?,?,?,?,?,?)').run(identifier,await digest(value),extra.expires_at??now+3600,'premium',extra.revoked??0,extra.user_id??null);return value;}
  const register=(username,license_key,hardware_id=hardware)=>call('/v1/register','POST',{username,password,license_key,hardware_id});
  const valid=await key();
  assert.equal((await call('/v1/register','POST',{username:'empty-password',password:'',license_key:valid,hardware_id:hardware})).status,422);
  assert.equal((await call('/v1/register','POST',{username:'no-license',password,hardware_id:hardware})).status,403);
  assert.equal((await call('/v1/register','POST',{username:'no-hardware',password,license_key:valid})).status,422);
  assert.equal((await register('unknown-key','NOVYX-INVALID-INVALID')).status,403);
  assert.equal((await register('expired-key',await key({expires_at:now-1}))).status,403);
  assert.equal((await register('revoked-key',await key({revoked:1}))).status,403);
  assert.equal((await register('assigned-key',await key({user_id:'someone-else'}))).status,403);
  assert.equal((await register('gerry2.0',valid)).status,409);
  assert.equal(DB.db.prepare('SELECT COUNT(*) n FROM users').get().n,0);
  const registered=await register('license-user',valid);assert.equal(registered.status,201);assert(!(await registered.json()).access_token);
  assert.equal((await register('second-user',valid)).status,403);
  assert.equal(DB.db.prepare('SELECT COUNT(*) n FROM users').get().n,1);
  const user=DB.db.prepare('SELECT * FROM users').get(),license=DB.db.prepare('SELECT * FROM licenses WHERE key_hash=?').get(await digest(valid));
  assert.equal(user.role,'user');assert.equal(user.console_only,0);assert.equal(user.web_approved,0);
  assert.equal(license.user_id,user.id);assert.equal(license.hardware_bound,1);assert.equal(license.hardware_hash,await digest(hardware));
  assert.equal((await call('/v1/admin/login','POST',{username:'license-user',password})).status,401);
  const login=await (await call('/v1/login','POST',{username:'license-user',password,hardware_id:hardware})).json();assert(login.access_token);
  DB.db.prepare('INSERT INTO variables(id,name,user_id,value,permission) VALUES(?,?,?,?,?)').run('flag','premium_feature',null,'enabled','premium');
  DB.db.prepare('INSERT INTO files(id,storage_name,permission,enabled,max_bytes) VALUES(?,?,?,?,?)').run('payload','payload.bin','premium',1,100);
  await BUCKET.put('payload.bin',new TextEncoder().encode('private payload'));
  assert.equal((await call('/v1/variables/premium_feature','GET',undefined,login.access_token)).status,200);
  assert.equal(await (await call('/v1/files/payload/content','GET',undefined,login.access_token)).text(),'private payload');
  const otherHardware='registration-other-computer';
  assert.equal((await call('/v1/login','POST',{username:'license-user',password,hardware_id:otherHardware})).status,403);
  DB.db.prepare('UPDATE licenses SET expires_at=? WHERE id=?').run(now-1,license.id);
  assert.equal((await call('/v1/variables/premium_feature','GET',undefined,login.access_token)).status,403);
  assert(!JSON.stringify(DB.db.prepare('SELECT * FROM audit_logs').all()).includes(valid));
  const longPassword='p'.repeat(257),longKey=await key();
  assert.equal((await call('/v1/register','POST',{username:'long-password',password:longPassword,license_key:longKey,hardware_id:hardware})).status,201);
  assert.equal((await call('/v1/login','POST',{username:'long-password',password:longPassword,hardware_id:hardware})).status,200);
  DB.db.close();
});


test('license lists show newest inserts first and keep Default and Spoofer keys separate',async()=>{
  const DB=new Database(),password='license ordering test password',defaultId='00000000-0000-4000-8000-000000000001';
  const env={DB,BUCKET:new Bucket(),OWNER_USERNAME:'gerry2.0',LICENSE_DISPLAY_KEY:b64(crypto.getRandomValues(new Uint8Array(32)))};
  DB.db.prepare("INSERT INTO users(id,username,password_hash,role,console_only,created_at) VALUES(?,?,?,'admin',1,?)")
    .run(crypto.randomUUID(),'gerry2.0',await hashPassword(password),Math.floor(Date.now()/1000));
  let token='';
  const call=(path,method='GET',body,app=defaultId)=>api(new Request('https://test.invalid'+path+(path.includes('?')?'&':'?')+'application_id='+app,{method,headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},body:body===undefined?undefined:JSON.stringify(body)}),env);
  token=(await (await call('/v1/admin/login','POST',{username:'gerry2.0',password})).json()).access_token;
  assert(token);
  const spoofer=(await (await call('/v1/admin/applications','POST',{name:'Spoofer'})).json()).id;
  const issue=async(app,days,id)=>{
    const response=await call('/v1/admin/licenses','POST',{days},app);assert.equal(response.status,201);
    const license=await response.json();
    DB.db.prepare('UPDATE licenses SET id=? WHERE id=?').run(id,license.id);
    return {...license,id};
  };
  const older=await issue(defaultId,999,'zzzz-old'),other=await issue(spoofer,30,'spoofer-key'),newer=await issue(defaultId,1,'aaaa-new');
  // Previously revoked rows, including legacy keys, must stay out of the list and pagination.
  for(const app of [defaultId,spoofer])DB.db.prepare('INSERT INTO licenses(id,key_hash,expires_at,permission,revoked,application_id) VALUES(?,?,?,?,1,?)')
    .run(crypto.randomUUID(),await digest(crypto.randomUUID()),0,'premium',app);
  const list=async(app,offset=0)=>(await (await call('/v1/admin/licenses?offset='+offset,'GET',undefined,app)).json()).licenses;
  assert.deepEqual((await list(defaultId)).map(l=>l.key),[newer.key,older.key]);
  assert.deepEqual((await list(defaultId,1)).map(l=>l.key),[older.key]);
  assert.deepEqual((await list(spoofer)).map(l=>l.key),[other.key]);
  for(const [method,suffix,body] of [['DELETE','',undefined],['POST','/extend',{days:1}],['POST','/reset-hwid',{}]]){
    assert.equal((await call('/v1/admin/licenses/'+other.id+suffix,method,body,defaultId)).status,404);
  }
  assert.equal(DB.db.prepare('SELECT revoked FROM licenses WHERE id=?').get(other.id).revoked,0);
  assert.equal((await call('/v1/admin/licenses/'+other.id,'DELETE',undefined,spoofer)).status,200);
  assert.equal(DB.db.prepare('SELECT 1 FROM licenses WHERE id=?').get(other.id),undefined);
  assert.deepEqual(await list(spoofer),[]);
  assert.deepEqual((await list(defaultId)).map(l=>l.key),[newer.key,older.key]);
  assert.equal((await call('/v1/register','POST',{username:'deleted-key-user',password,license_key:other.key,hardware_id:'deleted-key-device'},spoofer)).status,403);
  assert(DB.db.prepare("SELECT 1 FROM audit_logs WHERE event='admin.license.revoke' AND target=?").get(other.id));
  DB.db.close();
});

test('applications isolate credentials, resources, sessions, bans and SID resets',async()=>{
  const DB=new Database(),BUCKET=new Bucket(),ownerId=crypto.randomUUID();
  const password='test account password',env={DB,BUCKET,OWNER_USERNAME:'gerry2.0',LICENSE_DISPLAY_KEY:b64(crypto.getRandomValues(new Uint8Array(32)))};
  DB.db.prepare("INSERT INTO users(id,username,password_hash,role,console_only,created_at) VALUES(?,?,?,'admin',1,?)").run(ownerId,'gerry2.0',await hashPassword(password),Math.floor(Date.now()/1000));
  const defaultId='00000000-0000-4000-8000-000000000001',sidA='S-1-5-21-480216436-1083687383-1159651439-500',sidB='S-1-5-21-480216436-1083687383-1159651439-501';
  const call=(path,method='GET',body,token='',app=defaultId,sid=sidA)=>api(new Request('https://test.invalid'+path,{method,headers:{'Content-Type':'application/json','x-application-id':app,'x-hardware-id':sid,...(token?{Authorization:'Bearer '+token}:{})},body:body===undefined?undefined:JSON.stringify(body)}),env);
  const owner=await (await call('/v1/admin/login','POST',{username:'gerry2.0',password})).json();assert(owner.access_token);
  assert.equal((await (await call('/v1/admin/applications','GET',undefined,owner.access_token)).json()).applications.length,1);
  const appA=(await (await call('/v1/admin/applications','POST',{name:'External'},owner.access_token)).json()).id;
  const appB=(await (await call('/v1/admin/applications','POST',{name:'Spoofer'},owner.access_token)).json()).id;
  assert(appA&&appB&&appA!==appB);
  const key=async app=>(await (await call('/v1/admin/licenses','POST',{days:1,hardware_bound:true},owner.access_token,app)).json()).key;
  const keyA=await key(appA),keyB=await key(appB);
  const register=(app,license,sid=sidA)=>call('/v1/register','POST',{username:'customer',password,license_key:license,hardware_id:sid},'',app,sid);
  assert.equal((await register(appA,keyB)).status,403);
  assert.equal((await register(appA,keyA)).status,201);assert.equal((await register(appB,keyB,sidB)).status,201);
  const login=async(app,sid=sidA)=>{const r=await call('/v1/login','POST',{username:'customer',password,hardware_id:sid},'',app,sid);return {status:r.status,...await r.json()};};
  let a=await login(appA),b=await login(appB,sidB);assert.equal(a.status,200);assert.equal(b.status,200);
  assert.equal((await login(appA,sidB)).status,403);
  const lookup=async app=>(await (await call('/v1/admin/users/lookup?username=customer','GET',undefined,owner.access_token,app)).json()).user;
  const userA=await lookup(appA),userB=await lookup(appB);assert.notEqual(userA.id,userB.id);
  assert.equal((await call('/v1/session','GET',undefined,a.access_token,appB)).status,403);
  assert.equal((await call('/v1/refresh','POST',{refresh_token:a.refresh_token,hardware_id:sidA},'',appB)).status,403);
  const rotated=await call('/v1/refresh','POST',{refresh_token:a.refresh_token,hardware_id:sidA},'',appA);assert.equal(rotated.status,200);a=await rotated.json();
  const varA=crypto.randomUUID(),varB=crypto.randomUUID();
  for(const [app,id,value] of [[appA,varA,'external'],[appB,varB,'spoofer']]) assert.equal((await call('/v1/admin/variables/'+id,'PUT',{name:'flag',value,permission:'premium'},owner.access_token,app)).status,200);
  assert.equal((await (await call('/v1/variables/flag','GET',undefined,a.access_token,appA)).json()).value,'external');
  assert.equal((await (await call('/v1/variables/flag','GET',undefined,b.access_token,appB,sidB)).json()).value,'spoofer');
  assert.equal((await call('/v1/admin/variables/'+varA,'PUT',{name:'flag',value:'wrong',permission:'premium'},owner.access_token,appB)).status,404);
  assert.equal((await call('/v1/admin/variables/'+varA,'DELETE',undefined,owner.access_token,appB)).status,404);
  const upload=async(app,value)=>(await api(new Request('https://test.invalid/v1/admin/files',{method:'POST',headers:{Authorization:'Bearer '+owner.access_token,'x-application-id':app},body:new TextEncoder().encode(value)}),env)).json();
  const fileA=await upload(appA,'file A'),fileB=await upload(appB,'file B');
  assert.equal(await (await call('/v1/files/'+fileA.id+'/content','GET',undefined,a.access_token,appA)).text(),'file A');
  assert.equal((await call('/v1/files/'+fileA.id+'/content','GET',undefined,b.access_token,appB,sidB)).status,403);
  assert.equal((await call('/v1/admin/files/'+fileA.id,'PUT',{storage_name:'anything.bin',permission:'premium',max_bytes:100,enabled:true},owner.access_token,appB)).status,404);
  const usersA=await (await call('/v1/admin/users','GET',undefined,owner.access_token,appA)).json();assert(usersA.users.some(u=>u.id===userA.id));assert(!usersA.users.some(u=>u.id===userB.id));
  assert.equal(usersA.users.find(u=>u.id===userA.id).licenses[0].key,keyA);
  assert(!JSON.stringify(usersA).includes(keyB));assert(!JSON.stringify(usersA).includes('gerry2.0'));
  assert.equal((await call('/v1/admin/users/'+userA.id+'/permissions','GET',undefined,owner.access_token,appB)).status,404);
  assert.equal((await call('/v1/admin/users/'+userA.id+'/reset-hwid','POST',{},owner.access_token,appB)).status,404);
  assert.equal((await call('/v1/admin/users/'+userA.id+'/reset-hwid','POST',{},owner.access_token,appA)).status,200);
  assert.equal((await call('/v1/session','GET',undefined,a.access_token,appA)).status,401);
  a=await login(appA,sidB);assert.equal(a.status,200);assert.equal((await login(appA,sidA)).status,403);
  assert.equal((await call('/v1/admin/users/'+userA.id+'/ban','POST',{},owner.access_token,appA)).status,200);
  assert.equal((await login(appA,sidB)).status,401);assert.equal((await call('/v1/session','GET',undefined,a.access_token,appA,sidB)).status,401);
  assert.equal((await call('/v1/admin/users/'+userA.id+'/unban','POST',{},owner.access_token,appA)).status,200);
  a=await login(appA,sidB);assert.equal(a.status,200);
  assert.equal((await call('/v1/admin/applications/'+appA,'PUT',{name:'External',status:'disabled'},owner.access_token)).status,200);
  assert.equal((await login(appA,sidB)).status,403);
  assert.equal((await call('/v1/variables/flag','GET',undefined,b.access_token,appB,sidB)).status,200);
  assert.equal((await call('/v1/admin/applications/'+appA,'PUT',{name:'External',status:'active'},owner.access_token)).status,200);
  assert.equal((await login(appA,sidB)).status,200);
  assert(BUCKET.files.has(appA+'/upload-'+fileA.id));assert(BUCKET.files.has(appB+'/upload-'+fileB.id));
  assert.equal((await call('/v1/register','POST',{username:'invalid-app-user',password},'','invalid')).status,422);
  DB.db.close();
});


test('first application login requires a device ID and locks an unbound account to its SID',async()=>{
  const DB=new Database(),password='SID binding test password',userId=crypto.randomUUID();
  const env={DB,BUCKET:new Bucket(),LICENSE_DISPLAY_KEY:b64(crypto.getRandomValues(new Uint8Array(32)))};
  const sid='S-1-5-21-480216436-1083687383-1159651439-500',otherSid='S-1-5-21-480216436-1083687383-1159651439-501';
  DB.db.prepare("INSERT INTO users(id,username,password_hash,role,console_only,created_at) VALUES(?,?,?,'user',0,?)").run(userId,'sid-user',await hashPassword(password),Math.floor(Date.now()/1000));
  const call=(path,body,token='',device='')=>api(new Request('https://test.invalid'+path,{method:body?'POST':'GET',headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{}),...(device?{'x-hardware-id':device}:{})},body:body?JSON.stringify(body):undefined}),env);
  for(const hardware_id of [undefined,null,''])assert.equal((await call('/v1/login',{username:'sid-user',password,hardware_id})).status,422);
  assert.equal(DB.db.prepare('SELECT hardware_hash FROM users WHERE id=?').get(userId).hardware_hash,null);
  const result=await call('/v1/login',{username:'sid-user',password,hardware_id:sid});assert.equal(result.status,200);
  const session=await result.json();assert.equal(DB.db.prepare('SELECT hardware_hash FROM users WHERE id=?').get(userId).hardware_hash,await digest(sid));
  assert.equal((await call('/v1/login',{username:'sid-user',password,hardware_id:otherSid})).status,403);
  assert.equal((await call('/v1/session',undefined,session.access_token)).status,403);
  assert.equal((await call('/v1/session',undefined,session.access_token,otherSid)).status,403);
  assert.equal((await call('/v1/session',undefined,session.access_token,sid)).status,200);
  assert.equal((await call('/v1/refresh',{refresh_token:session.refresh_token,hardware_id:otherSid})).status,403);
  assert.equal((await call('/v1/refresh',{refresh_token:session.refresh_token,hardware_id:sid})).status,200);
  DB.db.close();
});


test('website sign-in accepts existing passwords of any nonempty length',async()=>{
  for(const password of ['x','p'.repeat(256)]){
    const DB=new Database(),userId=crypto.randomUUID();
    const env={DB,BUCKET:new Bucket(),OWNER_USERNAME:'owner',LICENSE_DISPLAY_KEY:b64(crypto.getRandomValues(new Uint8Array(32)))};
    DB.db.prepare("INSERT INTO users(id,username,password_hash,role,console_only,web_approved,created_at) VALUES(?,?,?,'admin',1,1,?)").run(userId,'owner',await hashPassword(password),Math.floor(Date.now()/1000));
    const login=value=>api(new Request('https://test.invalid/v1/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:'owner',password:value})}),env);
    assert.equal((await login('')).status,422);
    const result=await login(password);assert.equal(result.status,200);assert((await result.json()).access_token);
    assert.equal((await login('wrong')).status,401);
    DB.db.close();
  }
});


test('reseller accounts can only issue scoped keys and reset customer HWIDs',async()=>{
  const DB=new Database(),password='reseller test password',ownerId=crypto.randomUUID(),staffId=crypto.randomUUID(),now=Math.floor(Date.now()/1000);
  const env={DB,BUCKET:new Bucket(),OWNER_USERNAME:'owner',LICENSE_DISPLAY_KEY:b64(crypto.getRandomValues(new Uint8Array(32)))};
  for(const [id,username] of [[ownerId,'owner'],[staffId,'staff']])DB.db.prepare("INSERT INTO users(id,username,password_hash,role,console_only,web_approved,created_at) VALUES(?,?,?,'admin',1,1,?)").run(id,username,await hashPassword(password),now);
  const defaultApp='00000000-0000-4000-8000-000000000001';
  const call=(path,method='GET',body,token='',app=defaultApp,extra={})=>api(new Request('https://test.invalid'+path,{method,headers:{'Content-Type':'application/json','x-application-id':app,...(token?{Authorization:'Bearer '+token}:{}),...extra},body:body===undefined?undefined:JSON.stringify(body)}),env);
  const login=async username=>{const r=await call('/v1/admin/login','POST',{username,password,remember:true});return {response:r,data:await r.json()};};
  const owner=(await login('owner')).data,staff=(await login('staff')).data;
  const app=(await (await call('/v1/admin/applications','POST',{name:'External'},owner.access_token)).json()).id;
  const create=await call('/v1/admin/resellers','POST',{username:'partner',password,max_days:7},staff.access_token,app);assert.equal(create.status,201);const resellerId=(await create.json()).id;
  assert.equal((await call('/v1/admin/resellers','POST',{username:'partner',password,max_days:7},owner.access_token,app)).status,409);
  const {response,data:reseller}=await login('partner');assert.equal(response.status,200);assert.equal(reseller.user.role,'reseller');assert.equal(reseller.user.is_owner,false);
  const token=reseller.access_token;
  const apps=(await (await call('/v1/admin/applications','GET',undefined,token)).json()).applications;assert.deepEqual(apps.map(a=>a.id),[app]);
  assert.equal((await call('/v1/admin/reseller/licenses','GET',undefined,token)).status,403);
  assert.equal((await call('/v1/admin/reseller/licenses','POST',{days:8},token,app)).status,422);
  assert.equal((await call('/v1/admin/reseller/licenses','POST',{days:1,permission:'admin'},token,app)).status,422);
  const created=await call('/v1/admin/reseller/licenses','POST',{days:7},token,app);assert.equal(created.status,201);const issued=await created.json();assert.match(issued.key,/^NOVYX-/);assert.equal(issued.license.id,issued.id);assert.equal(issued.license.key,issued.key);assert.equal(issued.license.hardware_bound,1);assert.equal(issued.license.username,null);assert(issued.license.expires_at>now);
  const license=DB.db.prepare('SELECT * FROM licenses WHERE id=?').get(issued.id);assert.equal(license.reseller_id,resellerId);assert.equal(license.permission,'premium');assert.equal(license.hardware_bound,1);assert.equal(license.application_id,app);
  await call('/v1/admin/licenses','POST',{days:1},owner.access_token,app);
  const listed=(await (await call('/v1/admin/reseller/licenses','GET',undefined,token,app)).json()).reseller_licenses;assert.equal(listed.length,1);assert.equal(listed[0].key,issued.key);assert(!JSON.stringify(listed).includes('key_ciphertext'));
  const cookie=response.headers.get('Set-Cookie').split(';')[0];const restored=await call('/v1/admin/resume','POST',{},'',app,{Cookie:cookie,Origin:'https://test.invalid'});assert.equal(restored.status,200);assert.equal((await restored.json()).user.role,'reseller');
  const sid='S-1-5-21-480216436-1083687383-1159651439-500';
  assert.equal((await call('/v1/register','POST',{username:'customer',password,license_key:issued.key,hardware_id:sid},'',app)).status,201);
  const customer=DB.db.prepare("SELECT * FROM users WHERE username='customer'").get();
  const client=(await (await call('/v1/login','POST',{username:'customer',password,hardware_id:sid},'',app)).json());assert(client.access_token);
  assert.equal((await call('/v1/admin/reseller/reset-hwid','POST',{username:'customer'},token,defaultApp)).status,403);
  assert.equal((await call('/v1/admin/reseller/reset-hwid','POST',{username:'owner'},token,app)).status,404);
  assert.equal((await call('/v1/admin/reseller/reset-hwid','POST',{username:'CUSTOMER'},token,app)).status,200);
  assert.equal(DB.db.prepare('SELECT hardware_hash FROM users WHERE id=?').get(customer.id).hardware_hash,null);
  assert.equal(DB.db.prepare('SELECT hardware_hash FROM licenses WHERE id=?').get(issued.id).hardware_hash,null);
  assert.equal((await call('/v1/session','GET',undefined,client.access_token,app,{'x-hardware-id':sid})).status,401);
  assert.equal(DB.db.prepare('SELECT subscription_until FROM users WHERE id=?').get(customer.id).subscription_until,customer.subscription_until);
  for(const [path,method,body] of [
    ['/v1/admin/overview','GET'],['/v1/admin/users','GET'],['/v1/admin/users/lookup?username=customer','GET'],['/v1/admin/users/'+customer.id+'/ban','POST',{}],
    ['/v1/admin/licenses','GET'],['/v1/admin/licenses','POST',{days:1}],['/v1/admin/licenses/'+issued.id,'DELETE'],
    ['/v1/admin/variables','GET'],['/v1/admin/files','GET'],['/v1/admin/bootstrapper','GET'],['/v1/admin/audit','GET'],
    ['/v1/admin/applications','POST',{name:'Forbidden'}],['/v1/admin/resellers','POST',{username:'nested',password,max_days:1}],
    ['/v1/admin/resellers/'+resellerId,'PUT',{status:'active',max_days:999}],['/v1/admin/account','GET']
  ])assert.equal((await call(path,method,body,token,app)).status,403,path);
  assert.equal((await call('/v1/admin/reseller/licenses','POST',{days:1},client.access_token,app,{'x-hardware-id':sid})).status,401);
  const rotated=await call('/v1/refresh','POST',{refresh_token:reseller.refresh_token});assert.equal(rotated.status,200);
  const newToken=(await rotated.json()).access_token;assert.equal((await call('/v1/admin/reseller/licenses','GET',undefined,newToken,app)).status,200);
  assert.equal((await call('/v1/admin/resellers/'+resellerId,'PUT',{status:'suspended',max_days:7},staff.access_token,app)).status,200);
  assert.equal((await call('/v1/admin/reseller/licenses','GET',undefined,newToken,app)).status,401);
  assert.equal((await login('partner')).response.status,401);
  assert(DB.db.prepare("SELECT 1 FROM audit_logs WHERE event='reseller.user.hwid_reset' AND actor_id=?").get(resellerId));
  DB.db.close();
});
