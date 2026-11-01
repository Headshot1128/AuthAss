"""Package the current Windows DLL SDK with per-application setup instructions.

Run build_embedded_auth.py first to refresh the DLL and example binaries.
"""
from pathlib import Path
import zipfile


root = Path(__file__).resolve().parents[1]
output = root / 'build/novyx-application-sdk.zip'
curl = next((root / 'tools/sdk-build/curl').glob('curl-*'))
readme = """# NOVYX Application SDK (Windows x64, C++17)

## Create separate product panels

1. Sign in at https://novyx.online as the owner.
2. Open Applications > Create application and create External.
3. Repeat for Spoofer. Each product gets its own generated Application ID.
4. Use the Application selector in the sidebar to switch products.
5. Create licenses, users, variables and files with the intended product selected.
6. Copy each ID using Applications > Copy ID.

Users, licenses, subscriptions, files and variables are separate for each product.
Website administrators manage all products. Application IDs are public identifiers,
not passwords. Existing records remain in Default application.

## Configure your EXE

Open simple/main.cpp and replace the empty application_id string with the ID
copied from your panel. Build a separate EXE with each product's ID:

```cpp
const std::string application_id = "PASTE-APPLICATION-ID-FROM-PANEL";
novyx::Client auth("https://novyx.online", novyx::CurrentUserSid(), "", application_id);
if (!auth.Initialize()) return 1;
if (!auth.Login(username, password).success) return 1;
```

For the simple download example, also replace file_id with a file from the same
application and set output_path to a writable location. Never embed account
passwords or an owner password in your source.

In an x64 Visual Studio Developer Command Prompt, from the extracted ZIP folder:

```
cl /std:c++17 /EHsc /I include simple/main.cpp advapi32.lib /Fe:myapp.exe
```

For local runs, copy runtime/novyx_auth.dll and runtime/libcurl-x64.dll next to
myapp.exe. For distribution, select the matching application in the website,
open Bootstrapper, and upload myapp.exe. Distribute the resulting packaged EXE.
The precompiled example uses Default application until you rebuild it with an ID.

The larger example/main.cpp supports AUTH_APPLICATION_ID for local testing.
For distribution, compile your actual ID into your source as above so the panel
can verify that your uploaded EXE matches the selected application.

CurrentUserSid() binds to the Windows account SID. Existing device bindings may
need Reset HWID before switching to SID. Check success on every SDK operation.
Clients explicitly scoped to an ID reject tokens for a different application.
See embedded-auth.md for API calls and packaging details.
"""

with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as bundle:
    for name in ['abi.h', 'bootstrap.hpp', 'hardware.hpp']:
        bundle.write(root / 'sdk/include/novyx' / name, 'include/novyx/' + name)
    bundle.write(root / 'sdk/examples/simple/main.cpp', 'simple/main.cpp')
    bundle.write(root / 'sdk/examples/main.cpp', 'example/main.cpp')
    bundle.write(root / 'docs/embedded-auth.md', 'embedded-auth.md')
    bundle.write(root / 'build/embedded/novyx_auth.dll', 'runtime/novyx_auth.dll')
    bundle.write(curl / 'bin/libcurl-x64.dll', 'runtime/libcurl-x64.dll')
    bundle.write(root / 'build/embedded/novyx_dll_example.exe', 'novyx_dll_example.exe')
    bundle.writestr('README.md', readme)
print(output)
