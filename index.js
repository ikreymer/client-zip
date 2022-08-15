// src/polyfills.ts
if (!("stream" in Blob.prototype))
  Object.defineProperty(Blob.prototype, "stream", {
    value() {
      return new Response(this).body;
    }
  });
if (!("setBigUint64" in DataView.prototype))
  Object.defineProperty(DataView.prototype, "setBigUint64", {
    value(byteOffset, value, littleEndian) {
      const lowWord = Number(value & 0xffffffffn);
      const highWord = Number(value >> 32n);
      this.setUint32(byteOffset + (littleEndian ? 0 : 4), lowWord, littleEndian);
      this.setUint32(byteOffset + (littleEndian ? 4 : 0), highWord, littleEndian);
    }
  });

// src/utils.ts
var makeBuffer = (size) => new DataView(new ArrayBuffer(size));
var makeUint8Array = (thing) => new Uint8Array(thing.buffer || thing);
var encodeString = (whatever) => new TextEncoder().encode(String(whatever));
var clampInt32 = (n) => Math.min(4294967295, Number(n));
var clampInt16 = (n) => Math.min(65535, Number(n));

// src/input.ts
function normalizeInput(input, modDate) {
  if (modDate !== void 0 && !(modDate instanceof Date))
    modDate = new Date(modDate);
  if (input instanceof File)
    return {
      modDate: modDate || new Date(input.lastModified),
      bytes: input.stream()
    };
  if (input instanceof Response)
    return {
      modDate: modDate || new Date(input.headers.get("Last-Modified") || Date.now()),
      bytes: input.body
    };
  if (modDate === void 0)
    modDate = new Date();
  else if (isNaN(modDate))
    throw new Error("Invalid modification date.");
  if (typeof input === "string")
    return { modDate, bytes: encodeString(input) };
  if (input instanceof Blob)
    return { modDate, bytes: input.stream() };
  if (input instanceof Uint8Array || input instanceof ReadableStream)
    return { modDate, bytes: input };
  if (input instanceof ArrayBuffer || ArrayBuffer.isView(input))
    return { modDate, bytes: makeUint8Array(input) };
  if (Symbol.asyncIterator in input)
    return { modDate, bytes: ReadableFromIter(input) };
  throw new TypeError("Unsupported input format.");
}
function ReadableFromIter(iter) {
  const gen = "next" in iter ? iter : iter[Symbol.asyncIterator]();
  return new ReadableStream({
    async pull(controller) {
      let pushedSize = 0;
      while (controller.desiredSize > pushedSize) {
        const next = await gen.next();
        if (next.value) {
          const chunk = normalizeChunk(next.value);
          controller.enqueue(chunk);
          pushedSize += chunk.byteLength;
        } else {
          controller.close();
          break;
        }
      }
    }
  });
}
function normalizeChunk(chunk) {
  if (typeof chunk === "string")
    return encodeString(chunk);
  if (chunk instanceof Uint8Array)
    return chunk;
  return makeUint8Array(chunk);
}

// src/metadata.ts
function normalizeMetadata(input, encodedName, size) {
  if (encodedName !== void 0 && !(encodedName instanceof Uint8Array))
    encodedName = encodeString(encodedName);
  if (input instanceof File)
    return {
      encodedName: encodedName || encodeString(input.name),
      uncompressedSize: BigInt(input.size)
    };
  if (input instanceof Response) {
    const contentDisposition = input.headers.get("content-disposition");
    const filename = contentDisposition && contentDisposition.match(/;\s*filename\*?=["']?(.*?)["']?$/i);
    const urlName = filename && filename[1] || new URL(input.url).pathname.split("/").pop();
    const decoded = urlName && decodeURIComponent(urlName);
    const length = size || +input.headers.get("content-length");
    return { encodedName: encodedName || encodeString(decoded), uncompressedSize: BigInt(length) };
  }
  if (!encodedName || encodedName.length === 0)
    throw new Error("The file must have a name.");
  if (typeof input === "string")
    return { encodedName, uncompressedSize: BigInt(encodeString(input).length) };
  if (input instanceof Blob)
    return { encodedName, uncompressedSize: BigInt(input.size) };
  if (input instanceof ArrayBuffer || ArrayBuffer.isView(input))
    return { encodedName, uncompressedSize: BigInt(input.byteLength) };
  return { encodedName, uncompressedSize: size > -1 ? BigInt(size) : void 0 };
}

// src/crc32.ts
var wasm = "AGFzbQEAAAABCgJgAABgAn9/AXwDAwIAAQUDAQACBwkCAW0CAAFjAAEIAQAKlQECSQEDfwNAIAEhAEEAIQIDQCAAQQF2IABBAXFBoIbi7X5scyEAIAJBAWoiAkEIRw0ACyABQQJ0IAA2AgAgAUEBaiIBQYACRw0ACwtJAQF/IAFBf3MhAUGAgAQhAkGAgAQgAGohAANAIAFB/wFxIAItAABzQQJ0KAIAIAFBCHZzIQEgAkEBaiICIABJDQALIAFBf3O4Cw";
var instance = new WebAssembly.Instance(
  new WebAssembly.Module(Uint8Array.from(atob(wasm), (c2) => c2.charCodeAt(0)))
);
var { c, m } = instance.exports;
var pageSize = 65536;
var crcBuffer = makeUint8Array(m).subarray(pageSize);
function crc32(data, crc = 0) {
  for (const part of splitBuffer(data)) {
    crcBuffer.set(part);
    crc = c(part.length, crc);
  }
  return crc;
}
function* splitBuffer(data) {
  while (data.length > pageSize) {
    yield data.subarray(0, pageSize);
    data = data.subarray(pageSize);
  }
  if (data.length)
    yield data;
}

// src/datetime.ts
function formatDOSDateTime(date, into, offset = 0) {
  const dosTime = date.getSeconds() >> 1 | date.getMinutes() << 5 | date.getHours() << 11;
  const dosDate = date.getDate() | date.getMonth() + 1 << 5 | date.getFullYear() - 1980 << 9;
  into.setUint16(offset, dosTime, true);
  into.setUint16(offset + 2, dosDate, true);
}

// src/zip.ts
var fileHeaderSignature = 1347093252;
var fileHeaderLength = 30;
var descriptorSignature = 1347094280;
var descriptorLength = 16;
var centralHeaderSignature = 1347092738;
var centralHeaderLength = 46;
var endSignature = 1347093766;
var endLength = 22;
var zip64endRecordSignature = 1347094022;
var zip64endRecordLength = 56;
var zip64endLocatorSignature = 1347094023;
var zip64endLocatorLength = 20;
function contentLength(files) {
  let centralLength = BigInt(endLength);
  let offset = 0n;
  let archiveNeedsZip64 = false;
  for (const file of files) {
    if (!file.encodedName)
      throw new Error("Every file must have a non-empty name.");
    if (file.uncompressedSize === void 0)
      throw new Error(`Missing size for file "${new TextDecoder().decode(file.encodedName)}".`);
    const bigFile = file.uncompressedSize >= 0xffffffffn;
    const bigOffset = offset >= 0xffffffffn;
    offset += BigInt(fileHeaderLength + descriptorLength + file.encodedName.length + (bigFile && 8)) + file.uncompressedSize;
    centralLength += BigInt(file.encodedName.length + centralHeaderLength + (bigOffset * 12 | bigFile * 28));
    archiveNeedsZip64 || (archiveNeedsZip64 = bigFile);
  }
  if (archiveNeedsZip64 || offset >= 0xffffffffn)
    centralLength += BigInt(zip64endRecordLength + zip64endLocatorLength);
  return centralLength + offset;
}
async function* loadFiles(files) {
  const centralRecord = [];
  let offset = 0n;
  let fileCount = 0n;
  let archiveNeedsZip64 = false;
  for await (const file of files) {
    yield fileHeader(file);
    yield file.encodedName;
    yield* fileData(file);
    const bigFile = file.uncompressedSize >= 0xffffffffn;
    const bigOffset = offset >= 0xffffffffn;
    const zip64HeaderLength = bigOffset * 12 | bigFile * 28;
    yield dataDescriptor(file, bigFile);
    centralRecord.push(centralHeader(file, offset, zip64HeaderLength));
    centralRecord.push(file.encodedName);
    if (zip64HeaderLength)
      centralRecord.push(zip64ExtraField(file, offset, zip64HeaderLength));
    if (bigFile)
      offset += 8n;
    fileCount++;
    offset += BigInt(fileHeaderLength + descriptorLength + file.encodedName.length) + file.uncompressedSize;
    archiveNeedsZip64 || (archiveNeedsZip64 = bigFile);
  }
  let centralSize = 0n;
  for (const record of centralRecord) {
    yield record;
    centralSize += BigInt(record.length);
  }
  if (archiveNeedsZip64 || offset >= 0xffffffffn) {
    const endZip64 = makeBuffer(zip64endRecordLength + zip64endLocatorLength);
    endZip64.setUint32(0, zip64endRecordSignature);
    endZip64.setBigUint64(4, BigInt(zip64endRecordLength - 12), true);
    endZip64.setUint32(12, 755182848);
    endZip64.setBigUint64(24, fileCount, true);
    endZip64.setBigUint64(32, fileCount, true);
    endZip64.setBigUint64(40, centralSize, true);
    endZip64.setBigUint64(48, offset, true);
    endZip64.setUint32(56, zip64endLocatorSignature);
    endZip64.setBigUint64(64, offset + centralSize, true);
    endZip64.setUint32(72, 1, true);
    yield makeUint8Array(endZip64);
  }
  const end = makeBuffer(endLength);
  end.setUint32(0, endSignature);
  end.setUint16(8, clampInt16(fileCount), true);
  end.setUint16(10, clampInt16(fileCount), true);
  end.setUint32(12, clampInt32(centralSize), true);
  end.setUint32(16, clampInt32(offset), true);
  yield makeUint8Array(end);
}
function fileHeader(file) {
  const header = makeBuffer(fileHeaderLength);
  header.setUint32(0, fileHeaderSignature);
  header.setUint32(4, 754976768);
  formatDOSDateTime(file.modDate, header, 10);
  header.setUint16(26, file.encodedName.length, true);
  return makeUint8Array(header);
}
async function* fileData(file) {
  let { bytes } = file;
  if ("then" in bytes)
    bytes = await bytes;
  if (bytes instanceof Uint8Array) {
    yield bytes;
    file.crc = crc32(bytes, 0);
    file.uncompressedSize = BigInt(bytes.length);
  } else {
    file.uncompressedSize = 0n;
    for await (const value of bytes.iter) {
      file.crc = crc32(value, file.crc);
      file.uncompressedSize += BigInt(value.length);
    }
    yield { id: bytes.id, size: file.uncompressedSize };
  }
}
function dataDescriptor(file, needsZip64) {
  const header = makeBuffer(descriptorLength + (needsZip64 ? 8 : 0));
  header.setUint32(0, descriptorSignature);
  header.setUint32(4, file.crc, true);
  if (needsZip64) {
    header.setBigUint64(8, file.uncompressedSize, true);
    header.setBigUint64(16, file.uncompressedSize, true);
  } else {
    header.setUint32(8, clampInt32(file.uncompressedSize), true);
    header.setUint32(12, clampInt32(file.uncompressedSize), true);
  }
  return makeUint8Array(header);
}
function centralHeader(file, offset, zip64HeaderLength = 0) {
  const header = makeBuffer(centralHeaderLength);
  header.setUint32(0, centralHeaderSignature);
  header.setUint32(4, 755182848);
  header.setUint16(8, 2048);
  formatDOSDateTime(file.modDate, header, 12);
  header.setUint32(16, file.crc, true);
  header.setUint32(20, clampInt32(file.uncompressedSize), true);
  header.setUint32(24, clampInt32(file.uncompressedSize), true);
  header.setUint16(28, file.encodedName.length, true);
  header.setUint16(30, zip64HeaderLength, true);
  header.setUint16(40, 33204, true);
  header.setUint32(42, clampInt32(offset), true);
  return makeUint8Array(header);
}
function zip64ExtraField(file, offset, zip64HeaderLength) {
  const header = makeBuffer(zip64HeaderLength);
  header.setUint16(0, 1, true);
  header.setUint16(2, zip64HeaderLength - 4, true);
  if (zip64HeaderLength & 16) {
    header.setBigUint64(4, file.uncompressedSize, true);
    header.setBigUint64(12, file.uncompressedSize, true);
  }
  header.setBigUint64(zip64HeaderLength - 8, offset, true);
  return makeUint8Array(header);
}

// src/index.ts
function normalizeArgs(file) {
  return file instanceof File || file instanceof Response ? [[file], [file]] : [[file.input, file.name, file.size], [file.input, file.lastModified]];
}
function* mapMeta(files) {
  for (const file of files)
    yield normalizeMetadata(...normalizeArgs(file)[0]);
}
async function* mapFiles(files) {
  for await (const file of files) {
    const [metaArgs, dataArgs] = normalizeArgs(file);
    yield Object.assign(normalizeInput(...dataArgs), normalizeMetadata(...metaArgs));
  }
}
var predictLength = (files) => contentLength(mapMeta(files));
function downloadZip(files, options = {}) {
  const headers = { "Content-Type": "application/zip", "Content-Disposition": "attachment" };
  if ((typeof options.length === "bigint" || Number.isInteger(options.length)) && options.length > 0)
    headers["Content-Length"] = String(options.length);
  if (options.metadata)
    headers["Content-Length"] = String(predictLength(options.metadata));
  return new Response(ReadableFromIter(loadFiles(mapFiles(files))), { headers });
}
export {
  downloadZip,
  loadFiles,
  predictLength
};
