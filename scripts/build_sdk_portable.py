"""Build the Windows SDK probes with project-local Zig and curl."""
from pathlib import Path
import os
import shutil
import subprocess

root = Path(__file__).resolve().parents[1]
deps = root / 'tools/sdk-build'
zig = next((deps / 'zig').glob('*/zig.exe'))
curl = next((deps / 'curl').glob('curl-*'))
build = root / 'build/portable'
build.mkdir(parents=True, exist_ok=True)
env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(deps / 'cache'), ZIG_LOCAL_CACHE_DIR=str(build / 'cache'))
flags = [str(zig), 'c++', '-std=c++17', '-O1', '-Wall', '-Wextra', '-Wpedantic',
         '-I' + str(root / 'sdk/include'), '-I' + str(deps / 'include'), '-I' + str(curl / 'include')]
subprocess.run(flags + ['-c', str(root / 'sdk/src/client.cpp'), '-o', str(build / 'client.o')], check=True, env=env)
for target, source in [('auth_example', 'examples/main.cpp'), ('sdk_tests', 'tests/client_test.cpp'), ('sdk_e2e', 'tests/e2e.cpp'), ('sdk_live_probe', 'tests/live_probe.cpp')]:
    subprocess.run(flags + [str(root / 'sdk' / source), str(build / 'client.o'), str(curl / 'lib/libcurl.dll.a')] + (['-ladvapi32'] if target == 'auth_example' else []) + [
                           '-o', str(build / (target + '.exe'))], check=True, env=env)
    print('Built ' + target + '.exe', flush=True)
shutil.copy2(curl / 'bin/libcurl-x64.dll', build)
