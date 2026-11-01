import { z } from 'zod';
import { random, digest, hashPassword, verifyPassword } from './novyx-crypto.ts';

export type MailEnv={RESEND_API_KEY?:string;EMAIL_FROM?:string;PUBLIC_SITE_URL?:string};
const providerCodes=new Set(['validation_error','missing_api_key','invalid_api_key','restricted_api_key','rate_limit_exceeded','daily_quota_exceeded','monthly_quota_exceeded','application_error','security_error']);
class DeliveryError extends Error {constructor(public status:number,public code:string){super('email_delivery_failed');}}
export function emailReady(env:MailEnv){
  try {const url=new URL(env.PUBLIC_SITE_URL||'');return !!env.RESEND_API_KEY&&!!env.EMAIL_FROM&&url.protocol==='https:'&&url.pathname==='/'&&!url.search&&!url.hash&&!url.username&&!url.password;}catch{return false;}
}
// A fixed operator-configured origin prevents reset-link poisoning via request headers.
async function sendLink(env:MailEnv,email:string,purpose:string,token:string,username:string){
  const link=new URL('/',env.PUBLIC_SITE_URL);link.hash=new URLSearchParams({action:purpose,token}).toString();
  const verification=purpose==='verify-email';
  const result=await fetch('https://api.resend.com/emails',{method:'POST',redirect:'manual',signal:AbortSignal.timeout(10000),headers:{Authorization:'Bearer '+env.RESEND_API_KEY,'Content-Type':'application/json','User-Agent':'NOVYX-Auth/1.0'},body:JSON.stringify({from:env.EMAIL_FROM,to:[email],subject:verification?'Verify your NOVYX recovery email':'Reset your NOVYX password',text:`${verification?'Confirm this email address':'Choose a new password'} for NOVYX website account ${username}:\n\n${link.href}\n\nThis link expires in ${verification?'30':'15'} minutes and works once. If you did not request this, ignore this email.`})});
  if(!result.ok){const data=await result.json().catch(()=>null) as any;throw new DeliveryError(result.status,providerCodes.has(data?.name)?data.name:'provider_rejected');}
  await result.body?.cancel();
}
const emailSchema=z.string().trim().toLowerCase().email().max(254);
const tokenSchema=z.string().regex(/^[A-Za-z0-9_-]{64}$/);
export async function emailRecovery(ctx:any):Promise<Response|null>{
  const {path,method,env,one,run,stmt,db,body,deny,response,authenticated,throttle,audit,owner}=ctx;
  const now=()=>Math.floor(Date.now()/1000);
  const accessCondition="status='active' AND role='admin' AND (username=? OR web_approved=1)";
  const ownerName=(env.OWNER_USERNAME||'gerry2.0').toLowerCase();
  const eligible=(u:any)=>u&&u.status==='active'&&u.role==='admin'&&(owner(u,env)||u.web_approved===1);
  const generic=()=>response({message:'If an eligible website account uses that verified email, a reset link will arrive shortly.'});
  const requireMail=()=>{if(!emailReady(env))deny('email_not_configured',503);};
  async function issue(u:any,email:string,purpose:string){
    const token=random(48),hash=await digest(token);
    await db.batch([stmt('DELETE FROM email_tokens WHERE expires_at<=? OR (user_id=? AND purpose=?)',now(),u.id,purpose),stmt('INSERT INTO email_tokens(hash,user_id,purpose,email,credential_hash,expires_at) VALUES(?,?,?,?,?,?)',hash,u.id,purpose,email,u.password_hash,now()+(purpose==='verify-email'?1800:900))]);
    try {await sendLink(env,email,purpose,token,u.username);return true;}catch(error){
      // Never log provider messages: they can include recipients, keys or reset links.
      console.error(JSON.stringify({event:'email.delivery_failed',status:error instanceof DeliveryError?error.status:0,code:error instanceof DeliveryError?error.code:error instanceof Error&&['TypeError','TimeoutError','AbortError'].includes(error.name)?error.name:'transport_error'}));
      await run('DELETE FROM email_tokens WHERE hash=?',hash);await audit('email.delivery','denied');return false;
    }
  }
  if(path==='/v1/admin/account'&&method==='GET'){
    const u=await authenticated('admin');
    return response({username:u.username,email:u.email||null,email_verified:!!u.email_verified_at,email_delivery_ready:emailReady(env)});
  }
  if(path==='/v1/admin/account/email'&&method==='POST'){
    const u=await authenticated('admin');
    const b=await body(z.object({email:emailSchema,password:z.string().min(12).max(128)}).strict());
    requireMail();await throttle('email-change:'+u.id,3,900);
    if(!await verifyPassword(u.password_hash,b.password))deny('invalid_credentials');
    if(!await issue(u,b.email,'verify-email'))deny('email_delivery_failed',503);
    await audit('account.email.request','allowed',u.id);
    return response({message:'Check your inbox to verify this email. Your current recovery email stays active until you confirm.'});
  }
  if(path==='/v1/auth/email/verify'&&method==='POST'){
    const b=await body(z.object({token:tokenSchema}).strict());
    await throttle('verify-email-ip:'+ctx.ip,20,300);
    const hash=await digest(b.token),t=await one('SELECT * FROM email_tokens WHERE hash=? AND purpose=? AND used=0 AND expires_at>?',hash,'verify-email',now());
    const u=t?await one('SELECT * FROM users WHERE id=?',t.user_id):null;
    if(!eligible(u)||!t||u.password_hash!==t.credential_hash)deny('invalid_email_link',422);
    const result=await db.batch([
      stmt(`UPDATE users SET email=?,email_verified_at=? WHERE id=? AND password_hash=? AND ${accessCondition} AND EXISTS(SELECT 1 FROM email_tokens WHERE hash=? AND used=0 AND expires_at>?)`,t.email,now(),u.id,t.credential_hash,ownerName,hash,now()),
      stmt('UPDATE email_tokens SET used=1 WHERE user_id=? AND EXISTS(SELECT 1 FROM users WHERE id=? AND email=? AND password_hash=?)',u.id,u.id,t.email,t.credential_hash),
    ]);
    if(result[0].meta.changes!==1)deny('invalid_email_link',422);
    await audit('account.email.verified','allowed',u.id);return response({message:'Recovery email verified. You can now reset your password by email.'});
  }
  if(path==='/v1/auth/password/forgot'&&method==='POST'){
    const b=await body(z.object({email:emailSchema}).strict());requireMail();
    await throttle('forgot-ip:'+ctx.ip,10,900);await throttle('forgot-email:'+b.email,3,900);
    const users=(await stmt("SELECT * FROM users WHERE email=? AND email_verified_at IS NOT NULL AND (console_only=1 OR role='admin')",b.email).all()).results;
    // Addresses need not be unique; a mailbox may own multiple website accounts.
    // Each message names its account, and each token targets only that account.
    for(const u of users.filter(eligible).slice(0,10))await issue(u,b.email,'reset-password');
    return generic();
  }
  if(path==='/v1/auth/password/reset'&&method==='POST'){
    const b=await body(z.object({token:tokenSchema,password:z.string().min(12).max(128)}).strict());
    await throttle('reset-ip:'+ctx.ip,10,300);
    const hash=await digest(b.token),t=await one('SELECT * FROM email_tokens WHERE hash=? AND purpose=? AND used=0 AND expires_at>?',hash,'reset-password',now());
    const u=t?await one('SELECT * FROM users WHERE id=?',t.user_id):null;
    if(!t||!eligible(u)||u.password_hash!==t.credential_hash||u.email!==t.email||!u.email_verified_at)deny('invalid_email_link',422);
    const encoded=await hashPassword(b.password);
    const result=await db.batch([
      stmt(`UPDATE users SET password_hash=?,password_until=NULL WHERE id=? AND password_hash=? AND email=? AND ${accessCondition} AND EXISTS(SELECT 1 FROM email_tokens WHERE hash=? AND used=0 AND expires_at>?)`,encoded,u.id,t.credential_hash,t.email,ownerName,hash,now()),
      stmt('UPDATE sessions SET revoked=1 WHERE user_id=? AND EXISTS(SELECT 1 FROM users WHERE id=? AND password_hash=?)',u.id,u.id,encoded),
      stmt('UPDATE email_tokens SET used=1 WHERE user_id=? AND EXISTS(SELECT 1 FROM users WHERE id=? AND password_hash=?)',u.id,u.id,encoded),
    ]);
    if(result[0].meta.changes!==1)deny('invalid_email_link',422);
    await audit('account.password.reset','allowed',u.id);return response({message:'Password changed. Sign in with your new password.'});
  }
  return null;
}
