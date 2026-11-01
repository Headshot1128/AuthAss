export const MAX_APPLICATION_BYTES = 64 * 1024 * 1024;
const encoder = new TextEncoder();
const marker = encoder.encode('NOVYX_DLL_SDK_V1');

function contains(bytes, needle) {
  for (let i = bytes.indexOf(needle[0]); i !== -1; i = bytes.indexOf(needle[0], i + 1)) {
    if (needle.every((byte, offset) => bytes[i + offset] === byte)) return true;
  }
  return false;
}

export function validateApplication(bytes, applicationId) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 64 || bytes.length > MAX_APPLICATION_BYTES)
    throw new Error('Choose a nonempty Windows EXE up to 64 MiB.');
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const pe = view.getUint32(0x3c, true);
  if (view.getUint16(0, true) !== 0x5a4d || pe < 64 || pe + 24 > bytes.length ||
      view.getUint32(pe, true) !== 0x4550)
    throw new Error('This file is not a valid Windows executable.');
  const optionalSize = view.getUint16(pe + 20, true);
  const characteristics = view.getUint16(pe + 22, true);
  if (view.getUint16(pe + 4, true) !== 0x8664 || optionalSize < 112 ||
      pe + 24 + optionalSize > bytes.length || view.getUint16(pe + 24, true) !== 0x20b ||
      !(characteristics & 2) || (characteristics & 0x2000))
    throw new Error('Choose a Windows x64 EXE. DLLs and 32-bit applications are not supported.');
  if (!contains(bytes, marker))
    throw new Error('Rebuild your EXE with the Bootstrapper SDK first. The old static SDK cannot be converted after compilation.');
  if (applicationId && applicationId !== '00000000-0000-4000-8000-000000000001' && !contains(bytes,encoder.encode(applicationId)))
    throw new Error('Rebuild this EXE with the selected Application ID copied from Applications.');
}

export function packageApplication(template, application) {
  validateApplication(application);
  if (!(template instanceof Uint8Array) || template.length < 64 || template[0] !== 77 || template[1] !== 90)
    throw new Error('The bootstrap template is invalid. Refresh the page and try again.');
  const footer = new Uint8Array(24);
  footer.set(encoder.encode('NVXPKG01'));
  const view = new DataView(footer.buffer);
  view.setBigUint64(8, BigInt(application.length), true);
  view.setBigUint64(16, BigInt(template.length), true);
  return new Blob([template, application, footer], {type:'application/octet-stream'});
}

export async function sha256(bytes) {
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)),
    byte => byte.toString(16).padStart(2, '0')).join('');
}
