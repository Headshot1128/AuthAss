import handler from "vinext/server/fetch-handler";
import argon2Module from '../vendor/hash-wasm/argon2.wasm';
import blake2bModule from '../vendor/hash-wasm/blake2b.wasm';
import { configureWasmModules } from '../vendor/hash-wasm/lib/WASMInterface';
import { runWithConnectorBinding } from "../lib/connector-context";
import type { ConnectorBinding } from "../lib/connector-contract.mjs";
import { api, type Env } from '../lib/novyx-api';
import { trafficGuard, type TrafficEnv } from '../lib/traffic-guard';
import shell from '../web/index.html?raw';
import appScript from '../web/assets/app.js?raw';
import bootstrapScript from '../web/assets/bootstrapper.js?raw';
import sessionScript from '../web/assets/session-requests.js?raw';
import themeScript from '../web/assets/theme.js?raw';
import styles from '../web/assets/app.css?raw';
import themeStyles from '../web/assets/theme.css?raw';
import refinementStyles from '../web/assets/refinement.css?raw';
import interfaceStyles from '../web/assets/interface.css?raw';
import logo from '../web/assets/novyx.svg?raw';
import oldLogo from '../web/assets/mark.svg?raw';

configureWasmModules(argon2Module,blake2bModule);

async function serve(request:Request,env:Env & TrafficEnv) {
  const blocked=await trafficGuard(request,env);
  if(blocked)return blocked;
  const path=new URL(request.url).pathname;
  let result:Response;
  if(path.startsWith('/v1/')||path.startsWith('/_migration/')||path.startsWith('/_maintenance/'))result=await api(request,env);
  else if((path==='/'||path==='/admin')&&request.method==='GET')result=new Response(shell,{headers:{'Content-Type':'text/html; charset=utf-8'}});
  else {
    const assets:Record<string,[string,string]>={
      '/assets/app.js':[appScript,'application/javascript'], '/assets/theme.js':[themeScript,'application/javascript'],
      '/assets/bootstrapper.js':[bootstrapScript,'application/javascript'],
      '/assets/session-requests.js':[sessionScript,'application/javascript'],
      '/assets/refinement.css':[refinementStyles,'text/css'],
      '/assets/interface.css':[interfaceStyles,'text/css'],
      '/assets/app.css':[styles,'text/css'], '/assets/theme.css':[themeStyles,'text/css'], '/assets/fonts.css':['','text/css'],
      '/assets/novyx.svg':[logo,'image/svg+xml'], '/assets/mark.svg':[oldLogo,'image/svg+xml'],
    };
    const asset=assets[path];
    result=asset&&request.method==='GET'?new Response(asset[0],{headers:{'Content-Type':asset[1]+'; charset=utf-8'}}):Response.json({success:false,error:'not_found'},{status:404});
  }
  const response=new Response(result.body,result);
  response.headers.set('Cache-Control','no-store');response.headers.set('X-Content-Type-Options','nosniff');
  response.headers.set('Strict-Transport-Security','max-age=31536000');response.headers.set('Referrer-Policy','no-referrer');
  response.headers.set('X-Frame-Options','DENY');
  response.headers.set('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
  return response;
}

const worker = {
  fetch(request: Request, env: Cloudflare.Env, ctx: ExecutionContext<{ CONNECTORS?: ConnectorBinding }>) {
    let binding = ctx.props?.CONNECTORS;
    // Local preview emulates the same request-scoped capability. This branch and
    // the auxiliary service binding are absent from production builds.
    if (import.meta.env.DEV && !binding && env.CONNECTORS) {
      const preview = env.CONNECTORS;
      const expiresAt = Date.now() + 60_000;
      binding = {
        async getContext() {
          if (Date.now() >= expiresAt) return { status: "request_context_expired" };
          return preview.getContext?.() ?? { status: "binding_unavailable" };
        },
        async invoke(connectorId, actionName, args) {
          if (Date.now() >= expiresAt) {
            return { status: "request_context_expired", message: "This request has expired. Please try again." };
          }
          return preview.invoke(connectorId, actionName, args);
        },
      };
    }
    return runWithConnectorBinding(binding, () => serve(request, env as unknown as Env));
  },
};

export default worker;
