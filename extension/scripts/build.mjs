import { readdir, readFile, writeFile, mkdir, rm, cp } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { deflateRawSync } from 'node:zlib';
import { build } from 'esbuild';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
const manifest = JSON.parse(await readFile(path.join(root, 'src/manifest.json'), 'utf8'));
if (pkg.version !== manifest.version) throw new Error('Manifest and package versions differ');
const output = path.join(root, 'dist');
await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });
await cp(path.join(root, 'src'), output, { recursive: true });
// Only the domain helper needs bundling. No remote scripts or runtime lookup.
await build({
  entryPoints: [path.join(root, 'src/lib/domains.js')],
  outfile: path.join(output, 'lib/domains.js'),
  bundle: true, format: 'esm', platform: 'browser', target: 'chrome109',
  minify: true, legalComments: 'eof',
});
await cp(path.join(root, '../node_modules/tldts/LICENSE'), path.join(output, 'THIRD-PARTY-LICENSES.txt'));

async function files(folder, prefix = '') {
  const result = [];
  for (const entry of (await readdir(folder, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
    const name = `${prefix}${entry.name}`;
    if (entry.isDirectory()) result.push(...await files(path.join(folder, entry.name), `${name}/`));
    else if (entry.isFile()) result.push(name);
  }
  return result;
}
const crcTable = Array.from({ length: 256 }, (_, n) => {
  for (let k = 0; k < 8; k++) n = n & 1 ? 0xedb88320 ^ (n >>> 1) : n >>> 1;
  return n >>> 0;
});
function crc32(data) {
  let crc = 0xffffffff;
  for (const byte of data) crc = crcTable[(crc ^ byte) & 255] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}
const local = [], central = [];
let offset = 0;
for (const name of await files(output)) {
  const filename = Buffer.from(name);
  const data = await readFile(path.join(output, name));
  const compressed = deflateRawSync(data, { level: 9 });
  const crc = crc32(data);
  const header = Buffer.alloc(30);
  header.writeUInt32LE(0x04034b50, 0); header.writeUInt16LE(20, 4); header.writeUInt16LE(0x800, 6);
  header.writeUInt16LE(8, 8); header.writeUInt16LE(33, 12); header.writeUInt32LE(crc, 14);
  header.writeUInt32LE(compressed.length, 18); header.writeUInt32LE(data.length, 22); header.writeUInt16LE(filename.length, 26);
  local.push(header, filename, compressed);
  const directory = Buffer.alloc(46);
  directory.writeUInt32LE(0x02014b50, 0); directory.writeUInt16LE(20, 4); directory.writeUInt16LE(20, 6);
  directory.writeUInt16LE(0x800, 8); directory.writeUInt16LE(8, 10); directory.writeUInt16LE(33, 14);
  directory.writeUInt32LE(crc, 16); directory.writeUInt32LE(compressed.length, 20); directory.writeUInt32LE(data.length, 24);
  directory.writeUInt16LE(filename.length, 28); directory.writeUInt32LE(offset, 42);
  central.push(directory, filename);
  offset += header.length + filename.length + compressed.length;
}
const centralBuffer = Buffer.concat(central);
const end = Buffer.alloc(22);
end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(central.length / 2, 8); end.writeUInt16LE(central.length / 2, 10);
end.writeUInt32LE(centralBuffer.length, 12); end.writeUInt32LE(offset, 16);
const archive = Buffer.concat([...local, centralBuffer, end]);
const zipName = `ohmypassword-extension-${pkg.version}.zip`;
await writeFile(path.join(root, zipName), archive);
console.log(`Built dist/ and ${zipName} (${archive.length.toLocaleString('en-US')} bytes)`);
