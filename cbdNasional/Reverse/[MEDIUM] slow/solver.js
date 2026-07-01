const fs = require('fs');
const crypto = require('crypto');

const STAGE_COUNT = 87;
const START_WASM = process.argv[2] || './main.wasm';
const RGB_OUT = process.argv[3] || './recovered.rgb';
const FLAG_OUT = process.argv[4] || './flag.txt';
const FINAL_PAYLOAD_OUT = './final_payload.bin';
const TARGET_BASE = 36914448;
const F19_INDEX = 19;

const importObject = { env: {
  get_random(x) { return (0x9e3779b9 ^ (x >>> 0)) >>> 0; },
  document_query(x) { return (0x85ebca6b ^ (x >>> 0)) >>> 0; },
}};

function readUleb(buf, pos) { let res = 0, shift = 0; while (true) { const b = buf[pos++]; res |= (b & 0x7f) << shift; if (b < 0x80) break; shift += 7; } return [res >>> 0, pos]; }
function readSleb(buf, pos) { let res = 0, shift = 0, b; while (true) { b = buf[pos++]; res |= (b & 0x7f) << shift; shift += 7; if (b < 0x80) break; } if (b & 0x40) res |= -(1 << shift); return [res | 0, pos]; }
function uleb(n) { const out = []; do { let b = n & 0x7f; n >>>= 7; if (n) b |= 0x80; out.push(b); } while (n); return Buffer.from(out); }
function readName(buf, pos) { let len; [len, pos] = readUleb(buf, pos); return [buf.subarray(pos, pos + len).toString('utf8'), pos + len]; }

function addFuncExport(bytes, name, idx) {
  const buf = Buffer.from(bytes);
  let pos = 8;
  while (pos < buf.length) {
    const sid = buf[pos++]; const sizeStart = pos; let size; [size, pos] = readUleb(buf, pos); const start = pos, end = pos + size;
    if (sid === 7) {
      let p = start, count; [count, p] = readUleb(buf, p);
      let q = p;
      for (let i = 0; i < count; i++) { let nm; [nm, q] = readName(buf, q); const kind = buf[q++]; let exIdx; [exIdx, q] = readUleb(buf, q); if (kind === 0 && nm === name) return buf; }
      const nb = Buffer.from(name, 'utf8');
      const payload = Buffer.concat([uleb(count + 1), buf.subarray(p, end), uleb(nb.length), nb, Buffer.from([0]), uleb(idx)]);
      return Buffer.concat([buf.subarray(0, sizeStart), uleb(payload.length), payload, buf.subarray(end)]);
    }
    pos = end;
  }
  throw new Error('export section not found');
}

function parseModuleInfo(bytes) {
  const buf = Buffer.from(bytes);
  let pos = 8, importedFuncs = 0, funcCount = 0;
  const codeBodies = [];
  let dataOffset = null, dataPayloadPos = null, dataSize = null;
  while (pos < buf.length) {
    const sid = buf[pos++]; let size; [size, pos] = readUleb(buf, pos); const start = pos, end = pos + size;
    if (sid === 2) { let p = start, n; [n, p] = readUleb(buf, p); for (let i = 0; i < n; i++) { let mod, nm; [mod, p] = readName(buf, p); [nm, p] = readName(buf, p); const kind = buf[p++]; if (kind === 0) { let tid; [tid, p] = readUleb(buf, p); importedFuncs++; } else if (kind === 1) { p++; let fl; [fl, p] = readUleb(buf, p); let mn; [mn, p] = readUleb(buf, p); if (fl & 1) { let mx; [mx, p] = readUleb(buf, p); } } else if (kind === 2) { p++; let fl; [fl, p] = readUleb(buf, p); let mn; [mn, p] = readUleb(buf, p); if (fl & 1) { let mx; [mx, p] = readUleb(buf, p); } } else if (kind === 3) p += 2; } }
    if (sid === 3) { let p = start, n; [n, p] = readUleb(buf, p); funcCount = n; }
    if (sid === 10) { let p = start, n; [n, p] = readUleb(buf, p); for (let i = 0; i < n; i++) { let bsz; [bsz, p] = readUleb(buf, p); codeBodies.push([p, bsz]); p += bsz; } }
    if (sid === 11) { let p = start, n; [n, p] = readUleb(buf, p); if (n < 1) throw new Error('no data segments'); const kind = buf[p++]; if (kind !== 0) throw new Error('unexpected data segment kind'); const op = buf[p++]; if (op !== 0x41) throw new Error('unexpected data offset opcode'); let off; [off, p] = readSleb(buf, p); if (buf[p++] !== 0x0b) throw new Error('bad const expr'); let sz; [sz, p] = readUleb(buf, p); dataOffset = off; dataPayloadPos = p; dataSize = sz; }
    pos = end;
  }
  return {buf, importedFuncs, codeBodies, dataOffset, dataPayloadPos, dataSize};
}

function readI32Const(buf, pos) { return readSleb(buf, pos); }
function extractCopyInfo(bytes) {
  const info = parseModuleInfo(bytes);
  const bodyIndex = 12 - info.importedFuncs; // stage_process wrapper calls function 12 in this build family.
  const [bodyStart, bodySize] = info.codeBodies[bodyIndex];
  let p = bodyStart; const end = bodyStart + bodySize;
  let localDecls; [localDecls, p] = readUleb(info.buf, p);
  for (let i = 0; i < localDecls; i++) { let cnt; [cnt, p] = readUleb(info.buf, p); p++; }
  const recent = [];
  while (p < end) {
    const op = info.buf[p++];
    if (op === 0x41) { let val; [val, p] = readI32Const(info.buf, p); recent.push(val >>> 0); if (recent.length > 12) recent.shift(); continue; }
    if (op === 0x10) { let target; [target, p] = readUleb(info.buf, p); if (target === 14) { const vals = recent; const dest = vals[vals.length - 3], src = vals[vals.length - 2], len = vals[vals.length - 1]; return {dest, src, len, dataOffset: info.dataOffset, dataPayloadPos: info.dataPayloadPos, dataSize: info.dataSize}; } continue; }
    // skip immediates for common opcodes in this small wrapper
    if ([0x20,0x21,0x22,0x23,0x24,0x0c,0x0d].includes(op)) { let tmp; [tmp, p] = readUleb(info.buf, p); }
    else if ([0x28,0x29,0x2c,0x2d,0x36,0x3a,0x3b].includes(op)) { let a,o; [a,p]=readUleb(info.buf,p); [o,p]=readUleb(info.buf,p); }
    else if (op === 0x42) { let tmp; [tmp,p]=readSleb(info.buf,p); }
    else if (op === 0x11) { let a,b; [a,p]=readUleb(info.buf,p); [b,p]=readUleb(info.buf,p); }
  }
  throw new Error('copy call not found');
}

const selected = []; for (let w = 0; w < 8; w++) for (let k = 0; k < 3; k++) selected.push(w * 4 + k);
function selectedMaskFrom32(buf32) { let y = 0n, r = 0; for (const bytePos of selected) { const v = buf32[bytePos]; for (let b = 0; b < 8; b++, r++) if ((v >>> b) & 1) y |= 1n << BigInt(r); } return y; }
function bytesFromBits(x) { const out = Buffer.alloc(24); for (let j = 0; j < 192; j++) if ((x >> BigInt(j)) & 1n) out[j >> 3] |= 1 << (j & 7); return out; }
function parityBigInt(x) { let p = 0; while (x) { p ^= 1; x &= x - 1n; } return p; }
function invertMatrixFromColumns(cols) { const n = 192; const rows = new Array(n).fill(0n); for (let col = 0; col < n; col++) { let c = cols[col]; for (let row = 0; row < n; row++) if ((c >> BigInt(row)) & 1n) rows[row] |= 1n << BigInt(col); } for (let row = 0; row < n; row++) rows[row] |= 1n << BigInt(n + row); for (let col = 0; col < n; col++) { let pivot = col; while (pivot < n && (((rows[pivot] >> BigInt(col)) & 1n) === 0n)) pivot++; if (pivot === n) throw new Error('singular matrix'); if (pivot !== col) { const tmp = rows[col]; rows[col] = rows[pivot]; rows[pivot] = tmp; } for (let r = 0; r < n; r++) if (r !== col && (((rows[r] >> BigInt(col)) & 1n) !== 0n)) rows[r] ^= rows[col]; } const mask = (1n << 192n) - 1n; return rows.map(row => (row >> 192n) & mask); }
function solveWithInverse(invRows, rhs) { let x = 0n; for (let i = 0; i < 192; i++) if (parityBigInt(invRows[i] & rhs)) x |= 1n << BigInt(i); return x; }
async function buildInverse(e, mem, inputPtr, outputPtr) { mem.fill(0, inputPtr, inputPtr + 24); e.f19(inputPtr, outputPtr, 0); const zero = selectedMaskFrom32(Buffer.from(mem.slice(outputPtr, outputPtr + 32))); const cols = []; for (let j = 0; j < 192; j++) { mem.fill(0, inputPtr, inputPtr + 24); mem[inputPtr + (j >> 3)] = 1 << (j & 7); e.f19(inputPtr, outputPtr, 0); cols.push(selectedMaskFrom32(Buffer.from(mem.slice(outputPtr, outputPtr + 32))) ^ zero); } return {zero, invRows: invertMatrixFromColumns(cols)}; }
function pkcs7Unpad(buf) { const pad = buf[buf.length - 1]; if (pad < 1 || pad > 16 || pad > buf.length) throw new Error('bad padding value ' + pad); for (let i = 0; i < pad; i++) if (buf[buf.length - 1 - i] !== pad) throw new Error('bad padding bytes'); return buf.subarray(0, buf.length - pad); }
function aesDecryptEcbNoPadding(ciphertext, key) { const decipher = crypto.createDecipheriv('aes-128-ecb', key, null); decipher.setAutoPadding(false); return Buffer.concat([decipher.update(ciphertext), decipher.final()]); }
function rc4Crypt(input, key) { const s = new Uint8Array(256); for (let i=0;i<256;i++) s[i]=i; let j=0; for (let i=0;i<256;i++){ j=(j+s[i]+key[i%key.length])&255; const t=s[i]; s[i]=s[j]; s[j]=t; } const out=Buffer.alloc(input.length); let i=0; j=0; for(let n=0;n<input.length;n++){ i=(i+1)&255; j=(j+s[i])&255; const t=s[i]; s[i]=s[j]; s[j]=t; const k=s[(s[i]+s[j])&255]; out[n]=input[n]^k; } return out; }

async function solveStage(stageIdx, wasmBytes) {
  const patched = addFuncExport(wasmBytes, 'f19', F19_INDEX);
  const {instance} = await WebAssembly.instantiate(patched, importObject);
  const e = instance.exports;
  const mem = new Uint8Array(e.memory.buffer);
  const inputPtr = Number(e.stage_input_ptr());
  const inputLen = Number(e.stage_input_len());
  const outputPtr = Number(e.stage_output_ptr());
  if (inputLen % 24 !== 0) throw new Error(`input length ${inputLen} not multiple of 24`);
  const blocks = inputLen / 24;
  const {zero, invRows} = await buildInverse(e, mem, inputPtr, outputPtr);
  const chunk = Buffer.alloc(inputLen);
  for (let b = 0; b < blocks; b++) {
    const targetBase = inputPtr - blocks * 32 - 17200;
    const target = selectedMaskFrom32(Buffer.from(mem.slice(targetBase + b * 32, targetBase + b * 32 + 32)));
    bytesFromBits(solveWithInverse(invRows, target ^ zero)).copy(chunk, b * 24);
  }
  // Compute AES key: first 16 bytes of SHA-1(chunk), matching the stage's SHA-1 then AES decryptor.
  const key = crypto.createHash('sha1').update(chunk).digest().subarray(0, 16);
  const copy = extractCopyInfo(wasmBytes);
  if (copy.src < copy.dataOffset || copy.src + copy.len > copy.dataOffset + copy.dataSize) throw new Error(`copy range outside data segment at stage ${stageIdx}`);
  const info = parseModuleInfo(wasmBytes);
  const encStart = info.dataPayloadPos + (copy.src - info.dataOffset);
  const encrypted = info.buf.subarray(encStart, encStart + copy.len);
  const plainPadded = aesDecryptEcbNoPadding(encrypted, key);
  const payload = pkcs7Unpad(plainPadded);
  return {chunk, payload, blocks, inputLen, copyLen: copy.len};
}

(async () => {
  let wasmBytes = fs.readFileSync(START_WASM);
  const chunks = [];
  let finalPayload = null;
  for (let stage = 0; stage < STAGE_COUNT; stage++) {
    const t0 = Date.now();
    const res = await solveStage(stage, wasmBytes);
    chunks.push(res.chunk);
    console.log(`stage ${stage}: blocks=${res.blocks} input=${res.inputLen} payload=${res.payload.length} ms=${Date.now()-t0}`);
    if (stage < STAGE_COUNT - 1) {
      if (!(res.payload[0] === 0 && res.payload[1] === 0x61 && res.payload[2] === 0x73 && res.payload[3] === 0x6d)) throw new Error(`decrypted stage ${stage} is not wasm: ${res.payload.subarray(0,8).toString('hex')}`);
      wasmBytes = res.payload;
    } else {
      finalPayload = res.payload;
    }
    if (global.gc) global.gc();
  }
  const rgb = Buffer.concat(chunks);
  fs.writeFileSync(RGB_OUT, rgb);
  fs.writeFileSync(FINAL_PAYLOAD_OUT, finalPayload);
  const flag = rc4Crypt(finalPayload, crypto.createHash('sha256').update(rgb).digest()).toString('utf8');
  fs.writeFileSync(FLAG_OUT, flag);
  console.log(`rgb=${rgb.length} finalPayload=${finalPayload.length}`);
  console.log(`FLAG: ${flag}`);
})();
