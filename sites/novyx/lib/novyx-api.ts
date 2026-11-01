import { resellers } from './resellers.ts';
import { z } from 'zod';
import { emailRecovery, type MailEnv } from './email-recovery.ts';
import { DEFAULT_APPLICATION, APPLICATION_ID } from './applications.ts';
import bootstrapManifest from './bootstrap-manifest.json' with {type:'json'};
import { digest, random, hashPassword, verifyPassword, encryptKey, decryptKey, licenseKey, equal, bytes } from './novyx-crypto.ts';
export type Env = MailEnv & { DB:D1Database; BUCKET:R2Bucket; ASSETS?:{fetch(request:Request):Promise<Response>}; OWNER_USERNAME?:string; LICENSE_DISPLAY_KEY:string; MIGRATION_TOKEN?:string; REGISTRATION?:string; OWNER_RECOVERY_TOKEN?:string; OWNER_RECOVERY_DEADLINE?:string; };
const time=()=>Math.floor(Date.now()/1000), id=()=>crypto.randomUUID();
const rememberName='__Host-novyx-remember';
const rememberCookie=(token='',age=0)=>`${rememberName}=${token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${Math.max(0,age)}`;
class Denial extends Error { constructor(public code:string,public status=401){super(code);} }
const deny=(code:string,status=401):never=>{throw new Denial(code,status);};
const name=z.string().regex(/^[A-Za-z0-9_.-]{3,64}$/), permission=z.string().regex(/^[a-zA-Z0-9_.:-]{1,100}$/);
const creds=z.object({username:name,password:z.string().min(12).max(128),hardware_id:z.string().min(16).max(256).nullable().optional()}).strict();
const applicationCreds=creds.extend({password:z.string().min(1)});
const days=z.number().int().min(1).max(999), deadline=z.number().int().nonnegative();
const variable=z.object({name:z.string().regex(/^[a-zA-Z0-9_.-]{1,100}$/),value:z.string().max(16384),permission,user_id:z.string().nullable().optional()}).strict();
const fileMeta=z.object({storage_name:z.string().regex(/^[a-zA-Z0-9_.-]{1,128}$/),permission,enabled:z.boolean().default(true),max_bytes:z.number().int().positive().max(1073741824)}).strict();
const owner=(u:any,env:Env)=>u.username===(env.OWNER_USERNAME||'gerry2.0').toLowerCase();
const allowed=(u:any,env:Env)=>(u.role==='admin'&&(owner(u,env)||u.web_approved===1))||(u.role==='reseller'&&u.web_approved===1);
function response(data:any,status=200){return Response.json({success:true,...data},{status});}
const success=()=>response({});
async function limitedBody(request:Request,max=32768){
  const reader=request.body?.getReader(); if(!reader) return new Uint8Array();
  const chunks:Uint8Array[]=[];let total=0;
  while(true){const {done,value}=await reader.read();if(done)break;total+=value.length;if(total>max){await reader.cancel();deny('request_too_large',413);}chunks.push(value);}
  const out=new Uint8Array(total);let offset=0;for(const chunk of chunks){out.set(chunk,offset);offset+=chunk.length;}return out;
}
export async function api(request:Request,env:Env):Promise<Response>{
  const url=new URL(request.url);
  const appId=request.headers.get('x-application-id')??url.searchParams.get('application_id')??DEFAULT_APPLICATION;
  if(new URL(request.url).protocol!=='https:' && !request.url.startsWith('http://127.0.0.1:') && !request.url.startsWith('http://localhost:'))return Response.json({success:false,error:'https_required'},{status:400});
  const db=env.DB.withSession('first-primary');
  const stmt=(sql:string,...values:any[])=>db.prepare(sql).bind(...values.map(v=>v===undefined?null:v));
  const one=async(sql:string,...values:any[])=>stmt(sql,...values).first<any>();
  const rows=async(sql:string,...values:any[])=>(await stmt(sql,...values).all<any>()).results;
  const run=async(sql:string,...values:any[])=>stmt(sql,...values).run();
  const audit=async(event:string,outcome:string,actor:string|null=null,target:string|null=null)=>run('INSERT INTO audit_logs(timestamp,actor_id,event,target,outcome,application_id) VALUES(?,?,?,?,?,?)',time(),actor,event,target,outcome,APPLICATION_ID.test(appId)?appId:DEFAULT_APPLICATION);
  let selectedApplication:any;
  async function application(client=false){
    if(!APPLICATION_ID.test(appId)|| (request.headers.has('x-application-id')&&url.searchParams.has('application_id')&&request.headers.get('x-application-id')!==url.searchParams.get('application_id')))deny('invalid_application',422);
    selectedApplication??=await one('SELECT * FROM applications WHERE id=?',appId);
    if(!selectedApplication&&appId===DEFAULT_APPLICATION)selectedApplication={id:appId,name:'Default application',status:'active'};
    if(!selectedApplication)deny('application_not_found',404);
    if(client&&selectedApplication.status!=='active')deny('application_disabled',403);
    return selectedApplication;
  }
  const storageKey=(name:string)=>appId===DEFAULT_APPLICATION?name:appId+'/'+name;
  const scopedUser=(target:string)=>one("SELECT * FROM users WHERE id=? AND ((application_id=? AND console_only=0 AND role='user') OR console_only=1 OR role='admin')",target,appId);
  async function throttle(bucket:string,limit:number,seconds=60){
    const result=await one(`INSERT INTO rate_limits(bucket,window_start,count) VALUES(?,?,1) ON CONFLICT(bucket) DO UPDATE SET
      count=CASE WHEN window_start>? THEN count+1 ELSE 1 END,
      window_start=CASE WHEN window_start>? THEN window_start ELSE excluded.window_start END RETURNING count`,await digest(bucket),time(),time()-seconds,time()-seconds);
    if(result.count>limit)deny('rate_limited',429);
  }
  async function authenticated(audience='client',requireOwner=false,count=true){
    const header=request.headers.get('authorization')||'';
    if(!header.startsWith('Bearer ')||header.length>512)deny('authentication_required');
    const u=await one(`SELECT u.*,s.id AS session_id,s.revoked,s.audience,s.expires_at AS session_expiry,
      u.hardware_hash AS account_hardware_hash,s.hardware_hash,a.expires_at AS access_expiry FROM access_tokens a JOIN sessions s ON a.session_id=s.id
      JOIN users u ON s.user_id=u.id WHERE a.hash=?`,await digest(header.slice(7)));
    if(!u)deny('invalid_token');
    if(u.status!=='active'||u.revoked)deny('revoked');
    if(Math.min(u.session_expiry,u.access_expiry)<=time()||(u.password_until!==null&&u.password_until<=time()))deny('expired');
    if(u.audience!==audience||(audience==='admin'&&!['admin','reseller'].includes(u.role)))deny('permission_denied',403);
    if(audience==='admin'&&!allowed(u,env))deny('website_approval_required');
    if(audience==='admin'&&u.role==='reseller'&&!((path==='/v1/admin/session'&&method==='GET')||(path==='/v1/admin/logout'&&method==='POST')||(path==='/v1/admin/applications'&&method==='GET')||((path==='/v1/admin/reseller/licenses'&&['GET','POST'].includes(method))||(path==='/v1/admin/reseller/reset-hwid'&&method==='POST'))))deny('permission_denied',403);
    if(audience==='client'&&(u.console_only||u.role==='admin'))deny('permission_denied',403);
    if(audience==='client'){
      await application(true);
      if(!u.hardware_hash||!u.account_hardware_hash)deny('hardware_required',422);
      if(u.application_id!==appId)deny('application_mismatch',403);
      if(u.account_hardware_hash&&u.account_hardware_hash!==await digest(request.headers.get('x-hardware-id')||''))deny('hardware_mismatch',403);
    }
    if(requireOwner&&!owner(u,env))deny('owner_required',403);
    if(u.hardware_hash&&await digest(request.headers.get('x-hardware-id')||'')!==u.hardware_hash)deny('hardware_mismatch',403);
    if(count)await throttle('session:'+u.session_id,120);
    return u;
  }
  async function entitled(u:any,required:string){
    if(u.frozen_at!=null)deny('subscription_frozen',403);
    if(u.subscription_until<=time())deny('subscription_expired',403);
    if(await one('SELECT 1 FROM permissions WHERE user_id=? AND permission=?',u.id,required))return;
    if(!await one('SELECT 1 FROM licenses WHERE application_id=? AND user_id=? AND permission=? AND revoked=0 AND frozen_at IS NULL AND expires_at>? AND (hardware_bound=0 OR hardware_hash=?)',appId,u.id,required,time(),u.hardware_hash))deny('permission_denied',403);
  }
  async function issue(sid:string,sessionExpiry:number,extra:Record<string,unknown>={}){
    const access=random(),refresh=random(48),expires=Math.min(time()+300,sessionExpiry);
    await db.batch([stmt('INSERT INTO access_tokens VALUES(?,?,?)',await digest(access),sid,expires),stmt('INSERT INTO refresh_tokens(hash,session_id) VALUES(?,?)',await digest(refresh),sid)]);
    return response({access_token:access,refresh_token:refresh,expires_at:expires,...extra});
  }
  async function body<T>(schema:z.ZodType<T>):Promise<T>{
    try{return schema.parse(JSON.parse(new TextDecoder().decode(await limitedBody(request))));}
    catch(e){if(e instanceof Denial)throw e;deny('invalid_request',422);}
  }
  const path=decodeURIComponent(url.pathname), method=request.method;
  const rememberedToken=(request.headers.get('cookie')||'').split(';').map(value=>value.trim()).find(value=>value.startsWith(rememberName+'='))?.slice(rememberName.length+1)||'';
  const offset=Math.max(0,Math.min(2147483647,parseInt(url.searchParams.get('offset')||'0')||0));
  try{
    if(path==='/v1/admin/resume'&&method==='POST'){
      await body(z.object({}).strict());
      if(request.headers.get('origin')!==url.origin)deny('permission_denied',403);
      if(!/^[A-Za-z0-9_-]{64}$/.test(rememberedToken))deny('authentication_required');
      await throttle('resume:'+(request.headers.get('cf-connecting-ip')||'unknown'),60);
      const s=await one(`SELECT s.*,u.username,u.status,u.role,u.web_approved,u.password_until FROM refresh_tokens r JOIN sessions s ON s.id=r.session_id JOIN users u ON u.id=s.user_id WHERE r.hash=? AND r.used=0`,await digest(rememberedToken));
      if(!s||s.audience!=='admin'||s.revoked||s.status!=='active'||!allowed(s,env))deny('revoked');
      if(s.hardware_hash)deny('hardware_mismatch',403);
      if(s.expires_at<=time()||(s.password_until!==null&&s.password_until<=time()))deny('expired');
      return issue(s.id,s.expires_at,{user:{username:s.username,user_id:s.user_id,is_owner:owner(s,env),role:s.role}});
    }
    if(path.startsWith('/v1/auth/')||path==='/v1/admin/account'||path==='/v1/admin/account/email'){
      const result=await emailRecovery({path,method,env,one,run,stmt,db,body,deny,response,authenticated,throttle,audit,owner,ip:request.headers.get('cf-connecting-ip')||'unknown'});
      if(result)return result;
    }
    if(path==='/_maintenance/owner-password'&&method==='POST'){
      // Out-of-band owner recovery is disabled unless an operator configures a
      // high-entropy secret and a short deadline through the hosting control plane.
      const secret=env.OWNER_RECOVERY_TOKEN||'',token=request.headers.get('x-owner-recovery-token')||'';
      const deadline=Number(env.OWNER_RECOVERY_DEADLINE),timestamp=time();
      if(secret.length<32||token.length<32||token.length>256||!Number.isSafeInteger(deadline)||
        deadline<=timestamp||deadline>timestamp+3600||
        !equal(bytes(await digest(secret)),bytes(await digest(token))))deny('permission_denied',403);
      const marker='owner-password-reset:'+await digest(secret);
      if(await one('SELECT 1 FROM migration_state WHERE id=?',marker))deny('recovery_already_used',409);
      await throttle(marker,5,300);
      const b=await body(z.object({username:name,user_id:z.string().uuid(),password:z.string().min(12).max(128)}).strict());
      const u=await one('SELECT * FROM users WHERE id=? AND username=? AND role=?',b.user_id,b.username.toLowerCase(),'admin');
      if(!u||!owner(u,env))deny('permission_denied',403);
      const encoded=await hashPassword(b.password);
      // Compare-and-set plus the durable one-use marker make the reset atomic.
      // A racing password change causes the entire operation to make no changes.
      const changed=await db.batch([
        stmt(`UPDATE users SET password_hash=?,password_until=NULL WHERE id=? AND username=? AND role='admin'
          AND password_hash=? AND NOT EXISTS(SELECT 1 FROM migration_state WHERE id=?)`,encoded,u.id,u.username,u.password_hash,marker),
        stmt(`UPDATE sessions SET revoked=1 WHERE user_id=? AND EXISTS(SELECT 1 FROM users WHERE id=? AND password_hash=?)
          AND NOT EXISTS(SELECT 1 FROM migration_state WHERE id=?)`,u.id,u.id,encoded,marker),
        stmt(`INSERT INTO audit_logs(timestamp,actor_id,event,target,outcome)
          SELECT ?,NULL,'maintenance.owner.password_reset',?,'allowed' WHERE EXISTS(SELECT 1 FROM users WHERE id=? AND password_hash=?)
          AND NOT EXISTS(SELECT 1 FROM migration_state WHERE id=?)`,timestamp,u.id,u.id,encoded,marker),
        stmt(`INSERT INTO migration_state(id,completed_at) SELECT ?,? WHERE EXISTS(SELECT 1 FROM users WHERE id=? AND password_hash=?)
          AND NOT EXISTS(SELECT 1 FROM migration_state WHERE id=?)`,marker,timestamp,u.id,encoded,marker),
      ]);
      if(changed[0].meta.changes!==1)deny('recovery_conflict',409);
      return response({username:u.username,user_id:u.id});
    }
    if(path==='/_migration/import'&&method==='POST'){
      const token=request.headers.get('x-migration-token')||'';
      if(!env.MIGRATION_TOKEN||!equal(bytes(await digest(token)),bytes(await digest(env.MIGRATION_TOKEN))))deny('permission_denied',403);
      if(await one('SELECT 1 FROM migration_state WHERE id=?','local-import')||await one('SELECT 1 FROM users LIMIT 1'))deny('migration_already_completed',409);
      let data:any;try{data=JSON.parse(new TextDecoder().decode(await limitedBody(request,4*1024*1024)));}catch{deny('invalid_request',422);}
      const columns:Record<string,string[]>={
        users:['id','username','password_hash','status','role','subscription_until','password_until','created_at','console_only','web_approved'],
        licenses:['id','key_hash','expires_at','permission','hardware_bound','hardware_hash','user_id','revoked','key_ciphertext'],
        permissions:['user_id','permission'],variables:['id','name','user_id','value','permission'],files:['id','storage_name','permission','enabled','max_bytes'],
        audit_logs:['timestamp','actor_id','event','target','outcome']};
      if(!Array.isArray(data.users)||data.users.length>10000||!data.users.some((u:any)=>owner(u,env)&&u.role==='admin'&&u.status==='active'))deny('invalid_import_owner',422);
      const batch=[stmt('INSERT INTO migration_state VALUES(?,?)','local-import',time())];
      for(const [table,fields] of Object.entries(columns)){
        if(!Array.isArray(data[table])||data[table].length>10000)deny('invalid_request',422);
        for(const original of data[table]){
          const row={...original};
          if(table==='licenses')row.key_ciphertext=row.display_key?await encryptKey(row.display_key,env.LICENSE_DISPLAY_KEY):null;
          if(table==='users')row.web_approved=0; // Owner bypass remains; every other website account needs approval.
          batch.push(stmt(`INSERT INTO ${table}(${fields.join(',')}) VALUES(${fields.map(()=>'?').join(',')})`,...fields.map(f=>row[f]??null)));
        }
      }
      await db.batch(batch);await audit('migration.import','allowed');return success();
    }
    if(path==='/v1/register'&&method==='POST'){
      await application(true);
      const b=await body(applicationCreds.extend({license_key:z.string().min(19).max(256).optional()}));await throttle('register:'+(request.headers.get('cf-connecting-ip')||'unknown'),5,300);
      if(!b.license_key&&env.REGISTRATION!=='true')deny('registration_disabled',403);
      const username=b.username.toLowerCase();
      if(username===(env.OWNER_USERNAME||'gerry2.0').toLowerCase()||await one("SELECT 1 FROM users WHERE username=? AND application_id=? AND console_only=0 AND role='user'",username,appId))deny('registration_failed',409);
      if(b.license_key){
        if(!b.hardware_id)deny('hardware_required',422);
        const keyHash=await digest(b.license_key),hardwareHash=await digest(b.hardware_id);
        const license=await one('SELECT * FROM licenses WHERE key_hash=? AND application_id=?',keyHash,appId);
        if(!license||license.revoked||license.frozen_at!=null||license.expires_at<=time()||license.user_id||license.hardware_hash)deny('invalid_license',403);
        const userId=id(),encoded=await hashPassword(b.password),timestamp=time();
        // Conditional insert and claim execute in one D1 transaction. Only one
        // concurrent registration can consume a key, including previously unbound keys.
        const result=await db.batch([
          stmt(`INSERT INTO users(id,username,password_hash,created_at,subscription_until,application_id,hardware_hash)
            SELECT ?,?,?,?,expires_at,?,? FROM licenses WHERE key_hash=? AND application_id=? AND revoked=0 AND frozen_at IS NULL AND expires_at>? AND user_id IS NULL AND hardware_hash IS NULL`,userId,username,encoded,timestamp,appId,hardwareHash,keyHash,appId,timestamp),
          stmt(`UPDATE licenses SET user_id=?,hardware_bound=1,hardware_hash=? WHERE key_hash=? AND revoked=0 AND frozen_at IS NULL AND expires_at>? AND user_id IS NULL AND hardware_hash IS NULL AND EXISTS(SELECT 1 FROM users WHERE id=?)`,userId,hardwareHash,keyHash,timestamp,userId),
        ]);
        if(!result[0].meta.changes||!result[1].meta.changes)deny('invalid_license',403);
        await audit('registration','allowed',userId);await audit('activation','allowed',userId,license.id);return response({},201);
      }
      await run('INSERT INTO users(id,username,password_hash,created_at,application_id) VALUES(?,?,?,?,?)',id(),username,await hashPassword(b.password),time(),appId);
      await audit('registration','allowed');return response({},201);
    }
    if(['/v1/login','/v1/admin/login'].includes(path)&&method==='POST'){
      const audience=path.includes('/admin/')?'admin':'client';
      if(audience==='client')await application(true);
      const b=await body(audience==='admin'?applicationCreds.extend({remember:z.boolean().optional()}):applicationCreds),username=b.username.toLowerCase();
      await throttle('login-ip:'+(request.headers.get('cf-connecting-ip')||'unknown'),30);await throttle('login-user:'+audience+':'+(audience==='admin'?DEFAULT_APPLICATION:appId)+':'+username,10,300);
      const u=audience==='admin'?await one("SELECT * FROM users WHERE username=? AND (console_only=1 OR role='admin')",username):await one("SELECT * FROM users WHERE username=? AND application_id=? AND console_only=0 AND role='user'",username,appId);
      // A full-cost dummy verification keeps unknown users on the same password path.
      const encoded=u?.password_hash||'$argon2id$v=19$m=65536,t=3,p=1$c29tZXJhbmRvbXNhbHR2YWw$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
      const valid=await verifyPassword(encoded,b.password);
      if(!valid||!u||u.status!=='active'||(u.password_until!==null&&u.password_until<=time())||
        (audience==='admin'&&!['admin','reseller'].includes(u.role))||(audience==='client'&&(u.console_only||u.role==='admin'))){await audit('login','denied');deny('invalid_credentials');}
      if(audience==='admin'&&!allowed(u,env))deny('website_approval_required',403);
      if(audience==='client'){
        if(!b.hardware_id)deny('hardware_required',422);
        const hardware=b.hardware_id?await digest(b.hardware_id):null;
        if(u.hardware_hash&&u.hardware_hash!==hardware)deny('hardware_mismatch',403);
        if(hardware){
          if(await one('SELECT 1 FROM licenses WHERE application_id=? AND user_id=? AND hardware_bound=1 AND revoked=0 AND frozen_at IS NULL AND expires_at>? AND hardware_hash IS NOT NULL AND hardware_hash<>?',appId,u.id,time(),hardware))deny('hardware_mismatch',403);
          await db.batch([
            stmt('UPDATE users SET hardware_hash=? WHERE id=? AND application_id=? AND hardware_hash IS NULL',hardware,u.id,appId),
            stmt('UPDATE licenses SET hardware_hash=? WHERE application_id=? AND user_id=? AND hardware_bound=1 AND revoked=0 AND frozen_at IS NULL AND expires_at>? AND hardware_hash IS NULL',hardware,appId,u.id,time()),
          ]);
        }
      }
      const remember=audience==='admin'&&'remember' in b&&b.remember===true;
      const sid=id(),until=time()+(remember?30*86400:86400);
      // Recheck mutable account state after expensive password verification.
      const current=await one('SELECT * FROM users WHERE id=?',u.id);
      if(!current||current.status!=='active'||current.password_hash!==encoded||
        (current.password_until!==null&&current.password_until<=time())||
        (audience==='client'&&(current.application_id!==appId||(current.hardware_hash&&current.hardware_hash!==(b.hardware_id?await digest(b.hardware_id):null))))||
        (audience==='admin'&&!allowed(current,env))||(audience==='client'&&(current.console_only||current.role==='admin')))deny('invalid_credentials');
      await run('INSERT INTO sessions VALUES(?,?,?,?,0,?)',sid,u.id,audience,until,b.hardware_id?await digest(b.hardware_id):null);
      await audit('login','allowed',u.id);const result=await issue(sid,until,audience==='admin'?{
        user:{username:current.username,user_id:current.id,is_owner:owner(current,env),role:current.role}}:{application_id:appId});
      if(audience==='admin'){
        let cookie='';
        if(remember){cookie=random(48);await run('INSERT INTO refresh_tokens(hash,session_id) VALUES(?,?)',await digest(cookie),sid);}
        result.headers.set('Set-Cookie',rememberCookie(cookie,remember?until-time():0));
      }
      return result;
    }
    if(path==='/v1/refresh'&&method==='POST'){
      const b=await body(z.object({refresh_token:z.string().min(32).max(256),hardware_id:z.string().min(16).max(256).nullable().optional()}).strict());
      await throttle('refresh:'+(request.headers.get('cf-connecting-ip')||'unknown'),60);
      const hash=await digest(b.refresh_token);
      const s=await one('SELECT r.used,s.*,u.application_id,u.status,u.password_until,u.role,u.console_only,u.username,u.web_approved FROM refresh_tokens r JOIN sessions s ON r.session_id=s.id JOIN users u ON s.user_id=u.id WHERE r.hash=?',hash);
      if(!s)deny('invalid_token');
      if(s.audience==='client'){await application(true);if(s.application_id!==appId)deny('application_mismatch',403);if(!s.hardware_hash)deny('hardware_required',422);}
      if(s.used){await run('UPDATE sessions SET revoked=1 WHERE id=?',s.id);await audit('refresh_replay','revoked',s.user_id);deny('revoked');}
      if(s.revoked||s.status!=='active'||(s.audience==='admin'&&!allowed(s,env))||(s.audience==='client'&&(s.console_only||s.role==='admin')))deny('revoked');
      if(s.expires_at<=time()||(s.password_until!==null&&s.password_until<=time()))deny('expired');
      if(s.hardware_hash&&await digest(b.hardware_id||'')!==s.hardware_hash)deny('hardware_mismatch',403);
      const claimed=await run('UPDATE refresh_tokens SET used=1 WHERE hash=? AND used=0',hash);
      if(!claimed.meta.changes){await run('UPDATE sessions SET revoked=1 WHERE id=?',s.id);deny('revoked');}
      await run('DELETE FROM access_tokens WHERE session_id=?',s.id);
      await audit('refresh','allowed',s.user_id);return issue(s.id,s.expires_at,s.audience==='client'?{application_id:appId}:{});
    }
    if(path==='/v1/session'&&method==='GET'){const u=await authenticated();return response({user_id:u.id,subscription_until:u.subscription_until});}
    if(path==='/v1/admin/session'&&method==='GET'){const u=await authenticated('admin');return response({username:u.username,user_id:u.id,is_owner:owner(u,env),role:u.role});}
    if(['/v1/logout','/v1/admin/logout'].includes(path)&&method==='POST'){const u=await authenticated(path.includes('/admin/')?'admin':'client');await limitedBody(request);await run('UPDATE sessions SET revoked=1 WHERE id=?',u.session_id);await audit('logout','allowed',u.id);const result=success();if(path==='/v1/admin/logout')result.headers.set('Set-Cookie',rememberCookie());return result;}
    if(path==='/v1/licenses/activate'&&method==='POST'){
      const u=await authenticated(),b=await body(z.object({key:z.string().min(19).max(256)}).strict());await throttle('activation:'+u.id,10,300);
      const l=await one('SELECT * FROM licenses WHERE key_hash=? AND application_id=?',await digest(b.key),appId);
      if(!l||l.revoked||l.frozen_at!=null||l.expires_at<=time()||(l.user_id&&l.user_id!==u.id)||(l.hardware_bound&&!u.hardware_hash)||(l.hardware_hash&&l.hardware_hash!==u.hardware_hash))deny('invalid_license',403);
      const claim=await run('UPDATE licenses SET user_id=?,hardware_hash=? WHERE id=? AND revoked=0 AND frozen_at IS NULL AND expires_at>? AND (user_id IS NULL OR user_id=?) AND (hardware_hash IS NULL OR hardware_hash=?)',u.id,l.hardware_bound?u.hardware_hash:null,l.id,time(),u.id,u.hardware_hash);
      if(!claim.meta.changes)deny('invalid_license',403);
      await run('UPDATE users SET subscription_until=MAX(subscription_until,?) WHERE id=?',l.expires_at,u.id);await audit('activation','allowed',u.id,l.id);return success();
    }
    let match;
    if((match=/^\/v1\/variables\/([^/]+)$/.exec(path))&&method==='GET'){
      const u=await authenticated(),v=await one('SELECT * FROM variables WHERE application_id=? AND name=? AND (user_id=? OR user_id IS NULL) ORDER BY user_id IS NULL LIMIT 1',appId,match[1],u.id);
      if(!v)deny('permission_denied',403);await entitled(u,v.permission);await audit('variable','allowed',u.id,v.id);return response({value:v.value});
    }
    if((match=/^\/v1\/files\/([^/]+)\/content$/.exec(path))&&method==='GET'){
      const u=await authenticated(),f=await one('SELECT * FROM files WHERE id=? AND application_id=? AND enabled=1',match[1],appId);if(!f)deny('permission_denied',403);await entitled(u,f.permission);
      const object=await env.BUCKET.get(storageKey(f.storage_name));if(!object||object.size>f.max_bytes)deny('file_unavailable',404);
      await audit('download','allowed',u.id,f.id);
      const source=object.body.getReader();let sent=0;
      const stream=new ReadableStream({async pull(controller){try{
        const current=await authenticated('client',false,false);await entitled(current,f.permission);
        const active=await one('SELECT enabled,permission FROM files WHERE id=? AND application_id=?',f.id,appId);if(!active?.enabled||active.permission!==f.permission)throw Error('revoked');
        const chunks:Uint8Array[]=[];let length=0;
        while(length<1048576){const next=await source.read();if(next.done)break;chunks.push(next.value);length+=next.value.length;}
        if(!length){controller.close();return;}sent+=length;
        if(sent>f.max_bytes)throw Error('too large');
        const chunk=new Uint8Array(length);let offset=0;for(const part of chunks){chunk.set(part,offset);offset+=part.length;}controller.enqueue(chunk);
      }catch{await source.cancel();controller.error(new Error('Transfer authorization ended'));}},async cancel(){await source.cancel();}});
      return new Response(stream,{headers:{'Content-Type':'application/octet-stream','Content-Length':String(object.size),'Content-Disposition':'attachment'}});
    }
    // Website identities and account creation stay owner-only. Approved website
    // users may manage existing application customers in the selected app.
    if(!path.startsWith('/v1/admin/'))deny('not_found',404);
    const customerDirectory=path==='/v1/admin/users'&&method==='GET'&&(url.searchParams.get('scope')||'application')==='application';
    const customerTarget=/^\/v1\/admin\/users\/([^/]+)(?:\/(reset-hwid|ban|unban))?$/.exec(path);
    const customerAction=(path==='/v1/admin/users/lookup'&&method==='GET')||!!(customerTarget&&(customerTarget[2]?method==='POST':['PUT','DELETE'].includes(method)));
    const u=await authenticated('admin',(path.startsWith('/v1/admin/users')&&!customerDirectory&&!customerAction));
    if(customerAction&&!owner(u,env)&&customerTarget&&customerTarget[1]!=='lookup'&&!await one("SELECT 1 FROM users WHERE id=? AND application_id=? AND console_only=0 AND role='user'",customerTarget[1],appId))deny('permission_denied',403);
    const resellerResult=await resellers({path,method,u,appId,one,rows,run,stmt,db,body,deny,response,audit,env,offset,application});
    if(resellerResult)return resellerResult;
    if(path==='/v1/admin/applications'&&method==='GET'){
      await run("INSERT OR IGNORE INTO applications(id,name,status,created_at) VALUES(?,?,'active',?)",DEFAULT_APPLICATION,'Default application',time());
      if(u.role==='reseller')return response({applications:await rows('SELECT * FROM applications WHERE id=?',u.application_id),default_application_id:u.application_id});
      return response({applications:await rows('SELECT * FROM applications ORDER BY created_at,id'),default_application_id:DEFAULT_APPLICATION});
    }
    if(path==='/v1/admin/applications'&&method==='POST'){
      const b=await body(z.object({name:z.string().trim().min(1).max(64)}).strict()),applicationId=id();
      await run("INSERT INTO applications(id,name,status,created_at) VALUES(?,?,'active',?)",applicationId,b.name,time());
      await audit('admin.application.create','allowed',u.id,applicationId);return response({id:applicationId,name:b.name,status:'active'},201);
    }
    if((match=/^\/v1\/admin\/applications\/([^/]+)$/.exec(path))&&method==='PUT'){
      const b=await body(z.object({name:z.string().trim().min(1).max(64),status:z.enum(['active','disabled'])}).strict());
      if(!await one('SELECT 1 FROM applications WHERE id=?',match[1]))deny('not_found',404);
      await db.batch([stmt('UPDATE applications SET name=?,status=? WHERE id=?',b.name,b.status,match[1]),
        ...(b.status==='disabled'?[stmt("UPDATE sessions SET revoked=1 WHERE audience='client' AND user_id IN (SELECT id FROM users WHERE application_id=? AND console_only=0 AND role='user')",match[1])]:[])]);
      await audit('admin.application.update','allowed',u.id,match[1]);return success();
    }
    await application();
    if(path==='/v1/admin/users/lookup'&&method==='GET'){
      const username=url.searchParams.get('username')||'';
      const user=await one("SELECT id,username,status,subscription_until,password_until,hardware_hash IS NOT NULL AS hwid_bound,role,console_only FROM users WHERE username=? AND application_id=? AND console_only=0 AND role='user'",username.toLowerCase(),appId);
      if(!user)deny('not_found',404);return response({user});
    }
    if((match=/^\/v1\/admin\/users\/([^/]+)\/(reset-hwid|ban|unban)$/.exec(path))&&method==='POST'){
      await limitedBody(request);
      const user=await one("SELECT * FROM users WHERE id=? AND application_id=? AND console_only=0 AND role='user'",match[1],appId);
      if(!user)deny('not_found',404);
      await db.batch([
        match[2]==='reset-hwid'?stmt('UPDATE users SET hardware_hash=NULL WHERE id=?',user.id):stmt('UPDATE users SET status=? WHERE id=?',match[2]==='ban'?'suspended':'active',user.id),
        ...(match[2]==='reset-hwid'?[stmt('UPDATE licenses SET hardware_hash=NULL WHERE user_id=? AND application_id=?',user.id,appId)]:[]),
        stmt('UPDATE sessions SET revoked=1 WHERE user_id=?',user.id),
      ]);
      await audit('admin.user.'+match[2],'allowed',u.id,user.id);return success();
    }
    if(path==='/v1/admin/bootstrapper'&&method==='GET'){
      return response(bootstrapManifest);
    }
    if(['/v1/admin/bootstrapper/template','/v1/admin/bootstrapper/sdk'].includes(path)&&method==='GET'){
      if(!env.ASSETS)deny('server_error',503);
      const sdk=path.endsWith('/sdk');
      const asset=await env.ASSETS!.fetch(new Request(new URL(sdk?'/bootstrap/novyx-bootstrap-sdk.zip':'/bootstrap/novyx-template.bin',request.url)));
      if(!asset.ok)deny('server_error',503);
      // These are packager inputs consumed by fetch, rather than navigational
      // downloads. A dedicated type avoids download-manager interception.
      return new Response(asset.body,{headers:{'Content-Type':'application/vnd.novyx.asset'}});
    }
    if(path==='/v1/admin/bootstrapper'&&method==='POST'){
      const b=await body(z.object({size:z.number().int().min(64).max(67108864),sha256:z.string().regex(/^[a-f0-9]{64}$/)}).strict());
      await audit('admin.bootstrapper.package','allowed',u.id,b.sha256);
      return success();
    }
    if(path==='/v1/admin/overview'&&method==='GET'){
      const counts=await one(`SELECT
        (SELECT COUNT(*) FROM users WHERE application_id=? AND console_only=0 AND role='user') AS users,
        (SELECT COUNT(*) FROM users WHERE application_id=? AND status='active' AND subscription_until>?) AS subscribers,
        (SELECT COUNT(*) FROM licenses WHERE application_id=? AND revoked=0 AND frozen_at IS NULL AND expires_at>?) AS licenses,
        (SELECT COUNT(*) FROM files WHERE application_id=? AND enabled=1) AS files`,appId,appId,time(),appId,time(),appId);
      const recent=await rows('SELECT * FROM audit_logs WHERE application_id=? ORDER BY id DESC LIMIT 8',appId);await audit('admin.overview.read','allowed',u.id);return response({counts,recent});
    }
    if(path==='/v1/admin/users'&&method==='GET'){
      const scope=url.searchParams.get('scope')||'application';
      if(!['application','website'].includes(scope))deny('invalid_request',422);
      const columns='id,username,status,role,console_only,web_approved,subscription_until,password_until,hardware_hash IS NOT NULL AS hwid_bound';
      if(scope==='website'){
        if(!owner(u,env))deny('owner_required',403);
        const users=await rows(`SELECT ${columns} FROM users WHERE console_only=1 OR role='admin' ORDER BY id LIMIT 100 OFFSET ?`,offset);
        await audit('admin.website_users.list','allowed',u.id);
        return response({users:users.map(user=>({...user,is_owner:owner(user,env)}))});
      }
      const users=await rows(`SELECT ${columns} FROM users WHERE application_id=? AND console_only=0 AND role='user' ORDER BY username,id LIMIT 100 OFFSET ?`,appId,offset);
      const keys=users.length?await rows(`SELECT id,user_id,key_ciphertext,expires_at,revoked FROM licenses WHERE application_id=? AND user_id IN (${users.map(()=>'?').join(',')}) ORDER BY expires_at DESC,id`,appId,...users.map(user=>user.id)):[];
      const licenses=await Promise.all(keys.map(async({key_ciphertext,...license})=>({...license,key:key_ciphertext?await decryptKey(key_ciphertext,env.LICENSE_DISPLAY_KEY):null})));
      await audit('admin.users.list','allowed',u.id);
      return response({users:users.map(user=>({...user,is_owner:false,licenses:licenses.filter(license=>license.user_id===user.id).map(({user_id,...license})=>license)}))});
    }
    if(path==='/v1/admin/users'&&method==='POST'){
      const b=await body(applicationCreds.extend({account_type:z.enum(['website','application']).default('website')}).refine(b=>b.account_type==='application'||(b.password.length>=12&&b.password.length<=128))),username=b.username.toLowerCase();
      if(username===(env.OWNER_USERNAME||'gerry2.0').toLowerCase()||await one(b.account_type==='application'?"SELECT 1 FROM users WHERE username=? AND application_id=? AND console_only=0 AND role='user'":"SELECT 1 FROM users WHERE username=? AND (console_only=1 OR role='admin')",...b.account_type==='application'?[username,appId]:[username]))deny('user_exists',409);
      const application=b.account_type==='application',userId=id();
      await run('INSERT INTO users(id,username,password_hash,role,console_only,created_at,application_id) VALUES(?,?,?,?,?,?,?)',userId,username,await hashPassword(b.password),application?'user':'admin',application?0:1,time(),application?appId:DEFAULT_APPLICATION);
      await audit('admin.user.create','allowed',u.id,userId);return response({id:userId,account_type:b.account_type},201);
    }
    if((match=/^\/v1\/admin\/users\/([^/]+)$/.exec(path))){
      const target=match[1],user=await scopedUser(target);if(!user)deny('not_found',404);
      if(method==='DELETE'){
        if(target===u.id)deny('cannot_delete_own_account',409);
        await db.batch([
          stmt('DELETE FROM access_tokens WHERE session_id IN (SELECT id FROM sessions WHERE user_id=?)',target),stmt('DELETE FROM refresh_tokens WHERE session_id IN (SELECT id FROM sessions WHERE user_id=?)',target),stmt('DELETE FROM sessions WHERE user_id=?',target),stmt('DELETE FROM permissions WHERE user_id=?',target),stmt('DELETE FROM variables WHERE user_id=?',target),stmt('UPDATE licenses SET revoked=1,user_id=NULL,hardware_hash=NULL WHERE user_id=?',target),stmt('DELETE FROM users WHERE id=?',target)]);
        await audit('admin.user.delete','allowed',u.id,target);return success();
      }
      if(method==='PUT'){
        const b=await body(z.object({status:z.enum(['active','suspended','revoked']),subscription_until:deadline,password_until:deadline.nullable().optional(),web_access:z.boolean().nullable().optional()}).strict());
        if(target===u.id&&(b.web_access===false||b.status!=='active'))deny('cannot_disable_own_access',409);
        if(!user.console_only&&user.role!=='admin'&&b.web_access!==undefined&&b.web_access!==null)deny('application_account_website_access',422);
        const batch=[stmt('UPDATE users SET status=?,subscription_until=?,password_until=? WHERE id=?',b.status,b.subscription_until,b.password_until??null,target)];
        if(b.web_access!==undefined&&b.web_access!==null){
          batch.push(stmt('UPDATE users SET role=?,console_only=1,web_approved=? WHERE id=?',b.web_access?'admin':'user',b.web_access?1:0,target));
          if(user.role!==(b.web_access?'admin':'user')||!user.console_only||user.web_approved!==(b.web_access?1:0))batch.push(stmt('UPDATE sessions SET revoked=1 WHERE user_id=?',target));
        }
        if(b.status!=='active')batch.push(stmt('UPDATE sessions SET revoked=1 WHERE user_id=?',target));
        await db.batch(batch);await audit('admin.user.update','allowed',u.id,target);return success();
      }
    }
    if((match=/^\/v1\/admin\/users\/([^/]+)\/revoke-sessions$/.exec(path))&&method==='POST'){if(!await scopedUser(match[1]))deny('not_found',404);await limitedBody(request);await run('UPDATE sessions SET revoked=1 WHERE user_id=?',match[1]);await audit('admin.sessions.revoke','allowed',u.id,match[1]);return success();}
    if((match=/^\/v1\/admin\/users\/([^/]+)\/permissions$/.exec(path))){
      if(!await scopedUser(match[1]))deny('not_found',404);
      if(method==='GET')return response({permissions:(await rows('SELECT permission FROM permissions WHERE user_id=? ORDER BY permission',match[1])).map(r=>r.permission)});
      if(method==='PUT'){const b=await body(z.object({permission,allowed:z.boolean()}).strict());if(!await one('SELECT 1 FROM users WHERE id=?',match[1]))deny('not_found',404);await run(b.allowed?'INSERT OR IGNORE INTO permissions VALUES(?,?)':'DELETE FROM permissions WHERE user_id=? AND permission=?',match[1],b.permission);await audit('admin.permission.update','allowed',u.id,match[1]);return success();}
    }
    if(path==='/v1/admin/licenses'&&method==='GET'){
      const licenses=await rows('SELECT l.id,l.expires_at,l.permission,l.hardware_bound,l.user_id,l.revoked,l.frozen_at,l.key_ciphertext,u.username FROM licenses l LEFT JOIN users u ON l.user_id=u.id AND u.application_id=l.application_id WHERE l.application_id=? AND l.revoked=0 ORDER BY l.rowid DESC LIMIT 100 OFFSET ?',appId,offset);
      const result=[];for(const l of licenses){const {key_ciphertext,...rest}=l;result.push({...rest,key:key_ciphertext?await decryptKey(key_ciphertext,env.LICENSE_DISPLAY_KEY):null});}
      await audit('admin.licenses.list','allowed',u.id);return response({licenses:result});
    }
    if(path==='/v1/admin/licenses'&&method==='POST'){
      const b=await body(z.object({days:days.default(30),permission:permission.default('premium'),hardware_bound:z.boolean().default(false)}).strict()),key=licenseKey(),licenseId=id();
      await run('INSERT INTO licenses(id,key_hash,expires_at,permission,hardware_bound,key_ciphertext,application_id) VALUES(?,?,?,?,?,?,?)',licenseId,await digest(key),time()+b.days*86400,b.permission,b.hardware_bound?1:0,await encryptKey(key,env.LICENSE_DISPLAY_KEY),appId);await audit('admin.license.create','allowed',u.id,licenseId);return response({id:licenseId,key},201);
    }
    if((match=/^\/v1\/admin\/licenses\/([^/]+)(?:\/(reset-hwid|extend|freeze))?$/.exec(path))){
      const l=await one('SELECT * FROM licenses WHERE id=? AND application_id=?',match[1],appId);if(!l)deny('not_found',404);
      if(method==='DELETE'&&!match[2]){
        const timestamp=time(),batch=[stmt('DELETE FROM licenses WHERE id=? AND application_id=?',l.id,appId)];
        if(l.user_id&&l.frozen_at!=null)batch.push(stmt('UPDATE users SET subscription_until=subscription_until+?-COALESCE(frozen_at,?),frozen_at=NULL WHERE id=? AND NOT EXISTS(SELECT 1 FROM licenses WHERE user_id=? AND frozen_at IS NOT NULL AND revoked=0)',timestamp,timestamp,l.user_id,l.user_id));
        await db.batch(batch);await audit('admin.license.revoke','allowed',u.id,l.id);return success();
      }
      if(method==='POST'&&match[2]){
        if(l.revoked)deny('license_revoked',409);
        if(match[2]==='freeze'){
          await limitedBody(request);
          const timestamp=time(),frozen=l.frozen_at==null;
          const batch=[frozen?stmt('UPDATE licenses SET frozen_at=? WHERE id=?',timestamp,l.id):stmt('UPDATE licenses SET expires_at=expires_at+?-frozen_at,frozen_at=NULL WHERE id=?',timestamp,l.id)];
          if(l.user_id)batch.push(frozen?stmt('UPDATE users SET frozen_at=COALESCE(frozen_at,?) WHERE id=?',timestamp,l.user_id):stmt('UPDATE users SET subscription_until=subscription_until+?-COALESCE(frozen_at,?),frozen_at=NULL WHERE id=? AND NOT EXISTS(SELECT 1 FROM licenses WHERE user_id=? AND frozen_at IS NOT NULL AND revoked=0)',timestamp,timestamp,l.user_id,l.user_id));
          await db.batch(batch);await audit(frozen?'admin.license.freeze':'admin.license.unfreeze','allowed',u.id,l.id);return response({frozen});
        }
        if(match[2]==='reset-hwid'){
          await limitedBody(request);
          if(!l.hardware_bound)deny('hardware_binding_disabled',409);
          const batch=[stmt('UPDATE licenses SET hardware_hash=NULL WHERE id=?',l.id)];if(l.user_id)batch.push(stmt('UPDATE users SET hardware_hash=NULL WHERE id=? AND application_id=?',l.user_id,appId),stmt("UPDATE sessions SET revoked=1 WHERE user_id=? AND audience='client'",l.user_id));await db.batch(batch);await audit('admin.license.hwid_reset','allowed',u.id,l.id);return success();
        }
        const b=await body(z.object({days}).strict());
        const updated=await one('UPDATE licenses SET expires_at=MAX(expires_at,?)+? WHERE id=? AND revoked=0 RETURNING expires_at,user_id',l.frozen_at??time(),b.days*86400,l.id);
        if(!updated)deny('license_revoked',409);
        if(updated.user_id)await run('UPDATE users SET subscription_until=MAX(subscription_until,?) WHERE id=?',updated.expires_at,updated.user_id);
        await audit('admin.license.extend','allowed',u.id,l.id);return response({expires_at:updated.expires_at});
      }
    }
    if(path==='/v1/admin/variables'&&method==='GET'){await audit('admin.variables.list','allowed',u.id);return response({variables:await rows('SELECT * FROM variables WHERE application_id=? ORDER BY name,id LIMIT 100 OFFSET ?',appId,offset)});}
    if((match=/^\/v1\/admin\/variables\/([^/]+)$/.exec(path))){
      const existing=await one('SELECT application_id FROM variables WHERE id=?',match[1]);if(existing&&existing.application_id!==appId)deny('not_found',404);
      if(method==='DELETE'){await run('DELETE FROM variables WHERE id=? AND application_id=?',match[1],appId);await audit('admin.variable.delete','allowed',u.id,match[1]);return success();}
      if(method==='PUT'){
        const b=await body(variable);if(b.user_id&&!await one("SELECT 1 FROM users WHERE id=? AND application_id=? AND console_only=0 AND role='user'",b.user_id,appId))deny('not_found',404);
        if(await one('SELECT 1 FROM variables WHERE application_id=? AND name=? AND user_id IS ? AND id<>?',appId,b.name,b.user_id??null,match[1]))deny('variable_exists',409);
        await run('INSERT INTO variables(id,name,user_id,value,permission,application_id) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,user_id=excluded.user_id,value=excluded.value,permission=excluded.permission WHERE variables.application_id=excluded.application_id',match[1],b.name,b.user_id??null,b.value,b.permission,appId);await audit('admin.variable.update','allowed',u.id,match[1]);return success();
      }
    }
    if(path==='/v1/admin/files'&&method==='POST'){
      const fileId=id(),storageName='upload-'+fileId;
      const content=await limitedBody(request,67108864);
      if(!content.length)deny('empty_file',422);
      await env.BUCKET.put(storageKey(storageName),content);
      try {
        await run('INSERT INTO files(id,storage_name,permission,enabled,max_bytes,application_id) VALUES(?,?,?,?,?,?)',fileId,storageName,'premium',1,67108864,appId);
      } catch(error) { await env.BUCKET.delete(storageKey(storageName));throw error; }
      await audit('admin.file.upload','allowed',u.id,fileId);
      return response({id:fileId,permission:'premium'},201);
    }
    if(path==='/v1/admin/files'&&method==='GET'){await audit('admin.files.list','allowed',u.id);return response({files:await rows('SELECT * FROM files WHERE application_id=? ORDER BY id LIMIT 100 OFFSET ?',appId,offset)});}
    if((match=/^\/v1\/admin\/storage\/([a-zA-Z0-9_.-]{1,128})$/.exec(path))&&method==='PUT'){
      if(['.','..'].includes(match[1]))deny('invalid_storage_file',422);
      const content=await limitedBody(request,67108864);await env.BUCKET.put(storageKey(match[1]),content);await audit('admin.storage.upload','allowed',u.id,match[1]);return success();
    }
    if((match=/^\/v1\/admin\/files\/([^/]+)$/.exec(path))&&method==='PUT'){
      const existing=await one('SELECT application_id FROM files WHERE id=?',match[1]);if(existing&&existing.application_id!==appId)deny('not_found',404);
      const b=await body(fileMeta),object=await env.BUCKET.head(storageKey(b.storage_name));if(!object||object.size>b.max_bytes)deny('invalid_storage_file',422);
      if(await one('SELECT 1 FROM files WHERE application_id=? AND storage_name=? AND id<>?',appId,b.storage_name,match[1]))deny('file_exists',409);
      await run('INSERT INTO files(id,storage_name,permission,enabled,max_bytes,application_id) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET storage_name=excluded.storage_name,permission=excluded.permission,enabled=excluded.enabled,max_bytes=excluded.max_bytes WHERE files.application_id=excluded.application_id',match[1],b.storage_name,b.permission,b.enabled?1:0,b.max_bytes,appId);await audit('admin.file.update','allowed',u.id,match[1]);return success();
    }
    if(path==='/v1/admin/audit'&&method==='GET'){
      const events=url.searchParams.get('recent')==='true'?await rows('SELECT * FROM audit_logs WHERE application_id=? ORDER BY id DESC LIMIT 100 OFFSET ?',appId,offset):await rows('SELECT * FROM audit_logs WHERE application_id=? AND id>? ORDER BY id LIMIT 100',appId,Math.max(0,parseInt(url.searchParams.get('after')||'0')||0));await audit('admin.audit.read','allowed',u.id);return response({events});
    }
    deny('not_found',404);
  }catch(error){
    const status=error instanceof Denial?error.status:500,code=error instanceof Denial?error.code:'server_error';
    try{await audit('request.denied',String(status));}catch{}
    const result=Response.json({success:false,error:code},{status});
    if(path==='/v1/admin/resume'&&request.headers.get('origin')===url.origin)result.headers.set('Set-Cookie',rememberCookie());
    return result;
  }
}
