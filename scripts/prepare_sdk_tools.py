"""Download isolated SDK build dependencies; verify published SHA-256 digests."""
import hashlib
import re
import zipfile
from pathlib import Path
import httpx

root = Path(__file__).resolve().parents[1] / 'tools' / 'sdk-build'
root.mkdir(parents=True, exist_ok=True)
with httpx.Client(timeout=180, follow_redirects=True, trust_env=False) as client:
    zig = client.get('https://ziglang.org/download/index.json').json()['0.14.1']['x86_64-windows']
    page = client.get('https://curl.se/windows/'); page.raise_for_status()
    links = re.findall(r'href="([^"]*win64-mingw.zip)"', page.text)
    print('Zig:', zig['tarball'], flush=True)
    print('curl packages:', links[:3], flush=True)
    if not links:
        raise SystemExit('No official curl package found')
    from urllib.parse import urljoin
    curl_url = urljoin(str(page.url), links[0])
    for label, url, expected in [('zig', zig['tarball'], zig['shasum']), ('curl', curl_url, None)]:
        if expected is None:
            checksum = client.get(url + '.txt'); checksum.raise_for_status()
            expected = re.search(r'\b[a-fA-F0-9]{64}\b', checksum.text).group().lower()
        archive = root / (label + '.zip')
        if not archive.exists() or hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
            data = client.get(url); data.raise_for_status()
            if hashlib.sha256(data.content).hexdigest() != expected:
                raise SystemExit(label + ' checksum mismatch')
            archive.write_bytes(data.content)
        target = root / label
        if not target.exists():
            with zipfile.ZipFile(archive) as bundle:
                bundle.extractall(target)
        print(label + ': verified and extracted', flush=True)
    header_url = 'https://raw.githubusercontent.com/nlohmann/json/v3.12.0/single_include/nlohmann/json.hpp'
    header = client.get(header_url); header.raise_for_status()
    dest = root / 'include' / 'nlohmann' / 'json.hpp'
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(header.content)
    print('JSON header downloaded from upstream v3.12.0', flush=True)
