# Embedded authentication DLL

## Application IDs and SID binding

Create products under **Applications** in the admin panel, then select the product
in the sidebar. Each Application ID has separate EXE accounts, keys, subscriptions,
variables, files and activity. Website administrators remain global. Existing data
stays in `00000000-0000-4000-8000-000000000001` (Default application); older clients
without an Application ID continue using that default.

```cpp
const std::string application_id = "COPY-YOUR-APPLICATION-ID-HERE";
novyx::Client auth("https://novyx.online", novyx::CurrentUserSid(), "", application_id);
if (!auth.Initialize()) return 1;
```

Put the actual UUID in the compiled source. Bootstrapper checks that a non-default
Application ID is present in the uploaded EXE. The ID selects a product; it is a
public identifier, not an authentication secret. Clients with an explicit ID fail
closed when a server does not confirm the same application in its token response.
`AUTH_APPLICATION_ID` selects the product in the larger example.

`CurrentUserSid()` reads the current Windows account SID, for example
`S-1-5-21-480216436-1083687383-1159651439-500`. This identifies a Windows account,
not a physical computer. The simple and larger examples now use SID by default.
Application login requires a nonempty device ID. The first successful login locks
an unbound account to the supplied SID; other SIDs are rejected on subsequent
logins, session checks, protected requests and refreshes. Reset HWID revokes
existing sessions and allows the next login to bind again.
Existing MachineGuid bindings need an owner-triggered reset before switching.

Under **Users**, choose **Find username** or use row actions to **Reset HWID**,
**Ban**, or **Unban** an EXE account in the selected app. Reset clears the account
and assigned license bindings and revokes sessions; the next successful login
binds the new SID. Ban immediately blocks sign-in and revokes sessions. Unban does
not extend expired licenses or subscriptions. Changing Application ID on an
already initialized client is rejected; create a separate client for each app.

## Package your own application in the admin panel

1. Open **Bootstrapper** in the NOVYX admin panel and download the SDK ZIP.
2. Add the ZIP's `include` directory to your compiler's include paths, and use
   `#include <novyx/bootstrap.hpp>` instead of the static `secureauth` client.
3. Construct `novyx::Client auth("https://novyx.online", hardware_id);` and use
   `Initialize()`, `Login()`, `RegisterWithLicense()`, `GetVariable()` and
   `downloadfile()` as in the existing example. Check each result's `success`.
   Do not link `client.cpp` or curl into your application.
4. Compile a Windows x64 EXE, choose it in **Bootstrapper**, and select
   **Build application**. The panel downloads `<your-name>-bootstrap.exe`.

The SDK is header-only and requires C++17. For the provided example on MSVC:

```powershell
cl /std:c++17 /EHsc /DNOVYX_DLL_CLIENT /I include example/main.cpp advapi32.lib /Fe:myapp.exe
```

The ZIP also includes a precompiled `novyx_dll_example.exe` for trying the panel.
For a simple Login/Register menu, compile `simple/main.cpp` and edit its `file_id`
and `output_path` constants. It uses a loop to return to login after registration.
With MSVC: `cl /std:c++17 /EHsc /I include simple/main.cpp advapi32.lib /Fe:myapp.exe`.
Your unpackaged EXE needs `novyx_auth.dll` beside it for local development; without
the DLL its client fails initialization. After packaging, the bootstrap supplies it.
The panel checks the PE format, x64 architecture, SDK marker and 64 MiB size limit.
It assembles the application in your browser; the selected EXE is not stored on the
server. Packaging requires an active, approved administrator session.

The resulting EXE embeds your compiled application, the authentication DLL and
curl. On launch it extracts them into a unique temporary directory, starts your
EXE with the original arguments and working directory, waits for it to exit, then
cleans up. The authentication implementation stays in the DLL, while your app
contains the DLL interface. Do not leave background child processes depending on
these temporary files after your main process exits. Bundle any other application
dependencies separately; this flow packages one EXE and the NOVYX dependencies.

Existing applications compiled against the static SDK must be rebuilt with this
SDK. Packaging cannot remove authentication already compiled into an EXE. This
version does not support 32-bit executables. The packaged output is unsigned;
the package reader currently expects its footer at the end of the file. Embedded
code can still be extracted and patched; the server remains
responsible for authorization.

## Build the bootstrap template locally

Build from the repository root with the existing portable SDK dependencies:

```powershell
.\.venv\Scripts\python.exe scripts/build_embedded_auth.py
```

Distribute only `build/embedded/novyx_bootstrap.exe`. It embeds `novyx_auth.dll`
and its curl dependency. At startup it creates a unique temporary directory,
writes the embedded DLLs there, and loads the authentication DLL by absolute path
with dependency lookup restricted to that directory and Windows system libraries.
The DLL runs the current example's login, registration and protected-download flow
inside the bootstrap process. Arguments, environment variables and exit codes
follow `auth_example`; the working directory stays unchanged. On normal exit the
bootstrap unloads the DLL and removes the temporary files. Forced termination can
leave a temporary directory behind.

The bootstrap executable contains no SDK implementation; the embedded DLL contains
the example and SDK. Standard Windows DLL loading requires extraction to disk.
Embedding does not encrypt the DLL or prevent extraction, debugging, or patches.
The backend still enforces every protected resource request.

Running the template without a packaged application runs the supplied example
inside the authentication DLL. The build also refreshes the admin panel's
`public/bootstrap` assets. Rebuild and republish the Site after changing the DLL
or SDK. The exported demo entry point must keep its `int(int, char**)` ABI and stop
its threads before returning so the bootstrap can unload it.
