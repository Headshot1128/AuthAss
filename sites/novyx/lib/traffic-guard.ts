type Limiter = { limit(options:{key:string}):Promise<{success:boolean}> };
export type TrafficEnv = { TRAFFIC_LIMITER?:Limiter; AUTH_LIMITER?:Limiter };

// Emergency fallback for deployments without native bindings. Bounded per isolate;
// native Cloudflare counters are shared within a location and are preferred.
const counters=new Map<string,{start:number;count:number}>();
const capacity=10000;
function localLimit(key:string,limit:number,now:number){
  const current=counters.get(key);
  if(current&&now-current.start<60000)return ++current.count<=limit;
  if(counters.size>=capacity){
    for(const [key,value] of counters)if(now-value.start>=60000)counters.delete(key);
    if(counters.size>=capacity)return false;
  }
  counters.set(key,{start:now,count:1});return true;
}
function reject(error:string,status:number,retry=false){
  return Response.json({success:false,error},{status,headers:{'Cache-Control':'no-store',...(retry?{'Retry-After':'60'}:{})}});
}
export async function trafficGuard(request:Request,env:TrafficEnv):Promise<Response|null>{
  const url=new URL(request.url),path=url.pathname;
  if(url.href.length>8192)return reject('request_too_large',414);
  // CF-Connecting-IP is supplied by Cloudflare. Never trust X-Forwarded-For.
  const ip=request.headers.get('cf-connecting-ip');
  if(ip){
    const key='ip:'+ip;
    const allowed=env.TRAFFIC_LIMITER? (await env.TRAFFIC_LIMITER.limit({key})).success:localLimit(key,300,Date.now());
    if(!allowed)return reject('rate_limited',429,true);
    const auth=/(?:login|register|refresh|resume)$/.test(path)||path.startsWith('/v1/auth/')||path.startsWith('/_maintenance/')||path.startsWith('/_migration/');
    if(auth){
      const allowed=env.AUTH_LIMITER?(await env.AUTH_LIMITER.limit({key})).success:localLimit('auth:'+key,30,Date.now());
      if(!allowed)return reject('rate_limited',429,true);
    }
  }else if(url.hostname!=='localhost'&&url.hostname!=='127.0.0.1'){
    return reject('client_ip_required',400);
  }
  if(path.startsWith('/v1/')||path.startsWith('/_maintenance/')||path.startsWith('/_migration/')){
    const length=request.headers.get('content-length');
    // File upload routes retain their existing streamed size limits.
    const upload=(request.method==='POST'&&path==='/v1/admin/files')||(request.method==='PUT'&&/^\/v1\/admin\/storage\/[^/]+$/.test(path));
    const max=path.startsWith('/_migration/')?4194304:32768;
    if(!upload&&length!==null&&(!/^\d+$/.test(length)||Number(length)>max))return reject('request_too_large',413);
  }
  return null;
}
