# C++ EXE license and resource verification

Verified 2026-10-23 (Asia/Taipei).

## Executables

- `build/portable/auth_example.exe`: username/password login, license activation, protected variable lookup, protected file download to `protected-download.bin`.
- `build/portable/sdk_tests.exe`: SDK failure/state tests.
- `build/portable/sdk_e2e.exe`: actual SDK/local HTTPS integration.
- `build/portable/sdk_live_probe.exe`: read-only live TLS and unauthenticated access checks. Its invalid login adds a denied-login audit event.

Keep `libcurl-x64.dll` beside the EXEs. The example saves the original binary file with `auth.downloadfile(file_id, path)`; it does not execute downloaded files. Tokens and protected variable values are not printed. Registration password and key input are visible in the console as requested; do not share screenshots containing credentials.

Double-click `build/portable/auth_example.exe` to open the interactive console at `https://novyx.online`:

1. **Login** asks for username and hidden password. It uses the account's saved license entitlement, with no key prompt.
2. **Register key** asks for a new username, visible password, and license key. A password is required without a password-length rule. A valid unused key creates an application account and binds the key to this computer, then explicitly logs in.

The EXE reads the Windows MachineGuid automatically (or `/etc/machine-id` on Linux). There is no manual HWID prompt. The server stores its SHA-256 hash; this is an abuse deterrent, not hardware attestation. Cloned or modified machine identifiers can be spoofed. `AUTH_HARDWARE_ID` remains an override for integration tests/custom embedding. Registration preserves the key's existing expiry date and does not grant website access. The window waits for Enter before closing.

## Results

The compiled SDK failure/state tests passed. Both real TLS integration tests passed, including the example executing separate processes with:

| Case | Result |
| --- | --- |
| Valid key, account, hardware and permissions | Variable fetched; exact binary file bytes saved |
| Invalid key | Activation denied; no output file |
| Different hardware from the bound device | Activation denied; no output file |
| Missing file permission | Download denied; no output file |
| Missing variable permission | Variable denied; no output file |
| Revoked key | Activation denied; no output file |
| Expired key | Activation denied; no output file |
| Register key while ordinary registration is disabled | Application account created and hardware-bound; exact file downloaded |
| Later login without a license key | Existing license checked; exact file downloaded |
| Reuse registration key for another account | Registration denied |
| Interactive registration and login with automatic Windows HWID | Both succeeded against disposable HTTPS server |
| Application passwords of 1 and 257 characters | Registration and later login succeeded in the real EXE and Worker API tests |

The hosted Worker integration suite also passed in an isolated database, including expiry enforcement on existing sessions, HWID reset, private storage, and license extension.

The actual compiled C++ client connected to `https://novyx.online` with TLS verification enabled. Invalid login was rejected as an authentication failure; direct unauthenticated variable/file requests returned HTTP 401. Python independently verified that unauthenticated license activation also returned 401.

**Live success path with a real key is not yet verified.** Before this update, the live site had only two website accounts and no variables or files; `larryjoker` did not exist. The updated server permits license-backed registration and the owner can also select Application (EXE) in Create user. Existing accounts and keys were not modified by the tests. To fetch the example's resources, configure variable `premium_feature` and private file ID `protected-file` with permission `premium`, matching the license. Ordinary registration without a key stays disabled. The full local Python suite passed 43 tests, including actual EXE registration, resource download and later login; both Worker API test groups passed. The browser test passed owner creation of application accounts and website/application isolation.

## Reproduce the build and local tests

From the project root in PowerShell:

```powershell
.\.venv\Scripts\python.exe scripts/prepare_sdk_tools.py
.\.venv\Scripts\python.exe scripts/build_sdk_portable.py
.\build\portable\sdk_tests.exe
$env:SDK_EXAMPLE_BINARY = "$PWD\build\portable\auth_example.exe"
$env:SDK_E2E_BINARY = "$PWD\build\portable\sdk_e2e.exe"
$env:PATH = 'C:\Program Files\Git\usr\bin;' + $env:PATH
.\.venv\Scripts\python.exe -m pytest -q tests/test_sdk_e2e.py tests/test_sdk_license_e2e.py
.\build\portable\sdk_live_probe.exe https://novyx.online
```

The portable helper downloads Zig 0.14.1 and the current official curl Windows package, checks their published SHA-256 digests, and downloads the upstream nlohmann JSON v3.12.0 header. Tools and build outputs are ignored by Git. These are a reproducible testing toolchain, separate from the existing CMake/Visual Studio build.

For automated login, supply `AUTH_USERNAME` and `AUTH_PASSWORD` through your local environment, then run `build\portable\auth_example.exe https://novyx.online`. Adding `register` requires `AUTH_LICENSE_KEY` and registers/binds that key before login; an optional key supplied to noninteractive login is activated explicitly for compatibility. Adding `interactive` shows the menu at an explicit HTTPS origin. Optional `AUTH_VARIABLE_NAME` and `AUTH_FILE_ID` select existing protected resources. Do not set `AUTH_CA_BUNDLE` to the local development certificate for production. Do not send credentials in chat or commit them to source. The EXE fails closed and reports which stage was denied.
