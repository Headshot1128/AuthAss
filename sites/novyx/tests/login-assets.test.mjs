import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import vm from 'node:vm';

test('all browser scripts parse before deployment',()=>{
  for(const file of readdirSync('web/assets').filter(name=>name.endsWith('.js'))){
    const result=spawnSync(process.execPath,['--check','web/assets/'+file],{encoding:'utf8'});
    assert.equal(result.status,0,result.stderr);
  }
});

test('login form fallback posts credentials instead of placing them in the URL',()=>{
  const html=readFileSync('web/index.html','utf8');
  const form=html.match(/<form\b[^>]*id="login-form"[^>]*>/)[0];
  assert.match(form,/method="post"/);
  assert.match(form,/action="\/v1\/admin\/login"/);
});

test('early page script removes legacy credential query parameters',()=>{
  let replacement;
  const context={URL,location:{href:'https://example.test/?username=example&password=test-secret&view=licenses#section'},history:{state:null,replaceState(...args){replacement=args[2];}},localStorage:{getItem(){return 'dark';}},document:{documentElement:{dataset:{}}}};
  vm.runInNewContext(readFileSync('web/assets/theme.js','utf8'),context);
  assert.equal(replacement,'/?view=licenses#section');
});
