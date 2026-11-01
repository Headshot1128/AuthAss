import { z } from 'zod';
import { digest, encryptKey, decryptKey, hashPassword, licenseKey } from './novyx-crypto.ts';

// Reseller routes are deliberately separate from the general administration API.
export async function resellers(ctx:any):Promise<Response|null>{
  const {path,method,u,appId,one,rows,run,stmt,db,body,deny,response,audit,env,offset,application}=ctx;
  const now=()=>Math.floor(Date.now()/1000);
  if(path==='/v1/admin/resellers'&&method==='GET'){
    await application();
    return response({resellers:await rows("SELECT u.id,u.username,u.status,u.created_at,r.max_days FROM users u JOIN reseller_profiles r ON r.user_id=u.id WHERE u.application_id=? AND u.role='reseller' ORDER BY u.username LIMIT 100 OFFSET ?",appId,offset)});
  }
  if(path==='/v1/admin/resellers'&&method==='POST'){
    await application();
    const b=await body(z.object({username:z.string().regex(/^[A-Za-z0-9_.-]{3,64}$/),password:z.string().min(12).max(128),max_days:z.number().int().min(1).max(999).default(30)}).strict());
    const username=b.username.toLowerCase(),id=crypto.randomUUID();
    if(username===(env.OWNER_USERNAME||'gerry2.0').toLowerCase()||await one('SELECT 1 FROM users WHERE username=? AND console_only=1',username))deny('user_exists',409);
    const hash=await hashPassword(b.password);
    await db.batch([
      stmt("INSERT INTO users(id,username,password_hash,role,console_only,web_approved,created_at,application_id) VALUES(?,?,?,'reseller',1,1,?,?)",id,username,hash,now(),appId),
      stmt('INSERT INTO reseller_profiles(user_id,max_days) VALUES(?,?)',id,b.max_days),
    ]);
    await audit('admin.reseller.create','allowed',u.id,id);return response({id,username},201);
  }
  const account=/^\/v1\/admin\/resellers\/([^/]+)$/.exec(path);
  if(account&&method==='PUT'){
    const b=await body(z.object({status:z.enum(['active','suspended']),max_days:z.number().int().min(1).max(999)}).strict());
    if(!await one("SELECT 1 FROM users WHERE id=? AND application_id=? AND role='reseller'",account[1],appId))deny('not_found',404);
    await db.batch([stmt('UPDATE users SET status=? WHERE id=?',b.status,account[1]),stmt('UPDATE reseller_profiles SET max_days=? WHERE user_id=?',b.max_days,account[1]),stmt('UPDATE sessions SET revoked=1 WHERE user_id=?',account[1])]);
    await audit('admin.reseller.update','allowed',u.id,account[1]);return response({});
  }
  if(!path.startsWith('/v1/admin/reseller/'))return null;
  if(u.role!=='reseller')deny('permission_denied',403);
  if(u.application_id!==appId)deny('application_mismatch',403);
  await application(true);
  const profile=await one('SELECT max_days FROM reseller_profiles WHERE user_id=?',u.id);
  if(!profile)deny('permission_denied',403);
  if(path==='/v1/admin/reseller/licenses'&&method==='GET'){
    const licenses=await rows('SELECT l.id,l.expires_at,l.hardware_bound,l.revoked,l.key_ciphertext,c.username FROM licenses l LEFT JOIN users c ON c.id=l.user_id WHERE l.application_id=? AND l.reseller_id=? ORDER BY l.rowid DESC LIMIT 100 OFFSET ?',appId,u.id,offset);
    const result=await Promise.all(licenses.map(async({key_ciphertext,...license}:any)=>({...license,key:key_ciphertext?await decryptKey(key_ciphertext,env.LICENSE_DISPLAY_KEY):null})));
    return response({reseller_licenses:result,max_days:profile.max_days});
  }
  if(path==='/v1/admin/reseller/licenses'&&method==='POST'){
    const b=await body(z.object({days:z.number().int().min(1).max(profile.max_days)}).strict());
    const id=crypto.randomUUID(),key=licenseKey(),expires_at=now()+b.days*86400;
    await run("INSERT INTO licenses(id,key_hash,expires_at,permission,hardware_bound,key_ciphertext,application_id,reseller_id) VALUES(?,?,?,'premium',1,?,?,?)",id,await digest(key),expires_at,await encryptKey(key,env.LICENSE_DISPLAY_KEY),appId,u.id);
    await audit('reseller.license.create','allowed',u.id,id);return response({id,key,license:{id,key,expires_at,hardware_bound:1,revoked:0,username:null}},201);
  }
  if(path==='/v1/admin/reseller/reset-hwid'&&method==='POST'){
    const b=await body(z.object({username:z.string().regex(/^[A-Za-z0-9_.-]{3,64}$/)}).strict());
    const customer=await one("SELECT id,username FROM users WHERE application_id=? AND username=? AND console_only=0 AND role='user'",appId,b.username.toLowerCase());
    if(!customer)deny('not_found',404);
    await db.batch([
      stmt('UPDATE users SET hardware_hash=NULL WHERE id=?',customer.id),
      stmt('UPDATE licenses SET hardware_hash=NULL WHERE user_id=? AND application_id=?',customer.id,appId),
      stmt('UPDATE sessions SET revoked=1 WHERE user_id=?',customer.id),
    ]);
    await audit('reseller.user.hwid_reset','allowed',u.id,customer.id);
    return response({username:customer.username,message:'HWID reset. The next successful login binds the new Windows account SID.'});
  }
  deny('permission_denied',403);return null;
}
