import { spawn } from 'node:child_process';
import path from 'node:path';
if (process.stdin.isTTY) process.stdin.setRawMode(true);
process.stdout.write('Ready for owner recovery JSON (input hidden).\n');
process.stdin.setEncoding('utf8');
let input = '';
process.stdin.on('data', chunk => {
  if (chunk.includes('\u0003')) process.exit(130);
  input += chunk;
  if (!/[\r\n]/.test(input)) return;
  process.stdin.removeAllListeners('data'); process.stdin.pause();
  if (process.stdin.isTTY) process.stdin.setRawMode(false);
  const value = JSON.parse(input.trim()); input = '';
  const child = spawn(path.resolve('.venv/Scripts/python.exe'), ['-m','scripts.reset_site_owner'],
    {stdio:['pipe','pipe','pipe'],windowsHide:true});
  child.stdout.pipe(process.stdout); child.stderr.pipe(process.stderr);
  child.stdin.end(JSON.stringify(value)+'\n');
  child.on('exit', code => process.exit(code ?? 1));
});
