import fs from 'fs';
import path from 'path';
import zlib from 'zlib';

/**
 * Generates a valid uncompressed PNG buffer of given size with a blue/indigo PhishGuard shield
 */
function createShieldPng(size) {
  const width = size;
  const height = size;

  // RGBA buffer (4 bytes per pixel + 1 filter byte per row)
  const rowBytes = width * 4;
  const rawData = Buffer.alloc((rowBytes + 1) * height);

  for (let y = 0; y < height; y++) {
    const rowOffset = y * (rowBytes + 1);
    rawData[rowOffset] = 0; // Filter type: None

    for (let x = 0; x < width; x++) {
      const pxOffset = rowOffset + 1 + x * 4;
      
      // Normalized coordinates [-1, 1]
      const nx = (x - width / 2) / (width / 2);
      const ny = (y - height / 2) / (height / 2);

      // Shield geometry approximation
      const inShield = (
        ny >= -0.8 &&
        ny <= 0.85 &&
        Math.abs(nx) <= (ny <= 0 ? 0.8 : 0.8 * (1 - (ny * ny * 0.7)))
      );

      if (inShield) {
        // Gradient Indigo/Cyan
        const t = (nx + ny + 2) / 4;
        const r = Math.floor(30 + t * 40);
        const g = Math.floor(100 + t * 90);
        const b = Math.floor(220 + t * 35);
        rawData[pxOffset] = r;     // R
        rawData[pxOffset + 1] = g; // G
        rawData[pxOffset + 2] = b; // B
        rawData[pxOffset + 3] = 255; // A
      } else {
        // Transparent
        rawData[pxOffset] = 0;
        rawData[pxOffset + 1] = 0;
        rawData[pxOffset + 2] = 0;
        rawData[pxOffset + 3] = 0;
      }
    }
  }

  // PNG Signature
  const pngSignature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

  // IHDR Chunk
  const ihdrData = Buffer.alloc(13);
  ihdrData.writeUInt32BE(width, 0);
  ihdrData.writeUInt32BE(height, 4);
  ihdrData.writeUInt8(8, 8); // bit depth 8
  ihdrData.writeUInt8(6, 9); // color type 6 (RGBA)
  ihdrData.writeUInt8(0, 10); // compression
  ihdrData.writeUInt8(0, 11); // filter
  ihdrData.writeUInt8(0, 12); // interlace

  const ihdrChunk = createChunk('IHDR', ihdrData);

  // IDAT Chunk (zlib compressed image data)
  const compressed = zlib.deflateSync(rawData);
  const idatChunk = createChunk('IDAT', compressed);

  // IEND Chunk
  const iendChunk = createChunk('IEND', Buffer.alloc(0));

  return Buffer.concat([pngSignature, ihdrChunk, idatChunk, iendChunk]);
}

function createChunk(type, data) {
  const len = data.length;
  const chunk = Buffer.alloc(8 + len + 4);
  chunk.writeUInt32BE(len, 0);
  chunk.write(type, 4, 4, 'ascii');
  data.copy(chunk, 8);

  const crc = calculateCrc32(chunk.subarray(4, 8 + len));
  chunk.writeUInt32BE(crc, 8 + len);
  return chunk;
}

// CRC32 table
const crcTable = new Uint32Array(256);
for (let n = 0; n < 256; n++) {
  let c = n;
  for (let k = 0; k < 8; k++) {
    if (c & 1) c = 0xedb88320 ^ (c >>> 1);
    else c = c >>> 1;
  }
  crcTable[n] = c;
}

function calculateCrc32(buf) {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    crc = crcTable[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

// Ensure icon directories exist
const extensionIconsDir = path.resolve('extension/icons');
const publicIconsDir = path.resolve('public/icons');

fs.mkdirSync(extensionIconsDir, { recursive: true });
fs.mkdirSync(publicIconsDir, { recursive: true });

const sizes = [16, 32, 48, 128];
for (const s of sizes) {
  const pngBuf = createShieldPng(s);
  fs.writeFileSync(path.join(extensionIconsDir, `icon${s}.png`), pngBuf);
  fs.writeFileSync(path.join(publicIconsDir, `icon${s}.png`), pngBuf);
}

console.log('Successfully generated PhishGuard extension icon assets in extension/icons and public/icons');
