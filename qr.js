globalThis.decodeTotpQr = (() => {
  // QR Model 2, versions 1–10. Columns follow the format bits (M, L, H, Q).
  // Block sizes and alignment positions are from ISO/IEC 18004:2015, Table 9 and Annex E.
  const blockCounts = [
    [1, 1, 1, 1], [1, 1, 1, 1], [1, 1, 2, 2], [2, 1, 4, 2], [2, 1, 4, 4],
    [4, 2, 4, 4], [4, 2, 5, 6], [4, 2, 6, 6], [5, 2, 8, 8], [5, 4, 8, 8],
  ];
  const parityLengths = [
    [10, 7, 17, 13], [16, 10, 28, 22], [26, 15, 22, 18], [18, 20, 16, 26], [24, 26, 22, 18],
    [16, 18, 28, 24], [18, 20, 26, 18], [22, 24, 26, 22], [22, 30, 24, 20], [26, 18, 28, 24],
  ];
  const alignmentCenters = [
    [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50],
  ];
  const masks = [
    (x, y) => (x + y) % 2 === 0,
    (x, y) => y % 2 === 0,
    (x) => x % 3 === 0,
    (x, y) => (x + y) % 3 === 0,
    (x, y) => (Math.floor(y / 2) + Math.floor(x / 3)) % 2 === 0,
    (x, y) => (x * y) % 2 + (x * y) % 3 === 0,
    (x, y) => ((x * y) % 2 + (x * y) % 3) % 2 === 0,
    (x, y) => ((x + y) % 2 + (x * y) % 3) % 2 === 0,
  ];
  const alphanumeric = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

  function finderMatches(read, left, top) {
    for (let y = 0; y < 7; y++) {
      for (let x = 0; x < 7; x++) {
        const distance = Math.max(Math.abs(x - 3), Math.abs(y - 3));
        if (read(left + x, top + y) !== Number(distance !== 2)) return false;
      }
    }
    return true;
  }

  function readFormat(read, size) {
    let near = 0;
    let far = 0;
    for (let bit = 0; bit < 15; bit++) {
      const x = bit < 8 ? 8 : bit === 8 ? 7 : 14 - bit;
      const y = bit < 6 ? bit : bit === 6 ? 7 : 8;
      near |= read(x, y) << bit;
      far |= (bit < 8 ? read(size - 1 - bit, 8) : read(8, size - 15 + bit)) << bit;
    }
    for (let format = 0; format < 32; format++) {
      let remainder = format << 10;
      for (let bit = 14; bit >= 10; bit--) {
        if (remainder & (1 << bit)) remainder ^= 0x537 << (bit - 10);
      }
      const encoded = ((format << 10) | remainder) ^ 0x5412;
      if (encoded === near || encoded === far) return format;
    }
    return -1;
  }

  function readCodewords(read, size, version, mask) {
    const reserved = new Uint8Array(size * size);
    function reserve(x, y, width, height) {
      for (let row = y; row < y + height; row++) {
        reserved.fill(1, row * size + x, row * size + x + width);
      }
    }
    reserve(0, 0, 9, 9);
    reserve(size - 8, 0, 8, 9);
    reserve(0, size - 8, 9, 8);
    reserve(0, 6, size, 1);
    reserve(6, 0, 1, size);
    const centers = alignmentCenters[version - 1];
    const last = size - 7;
    for (const y of centers) {
      for (const x of centers) {
        if ((x === 6 && (y === 6 || y === last)) || (x === last && y === 6)) continue;
        reserve(x - 2, y - 2, 5, 5);
      }
    }
    if (version >= 7) {
      reserve(size - 11, 0, 3, 6);
      reserve(0, size - 11, 6, 3);
    }

    const words = [];
    let byte = 0;
    let bits = 0;
    let upwards = true;
    for (let right = size - 1; right > 0; right -= 2) {
      if (right === 6) right--;
      for (let row = 0; row < size; row++) {
        const y = upwards ? size - 1 - row : row;
        for (let x = right; x >= right - 1; x--) {
          if (reserved[y * size + x]) continue;
          byte = (byte << 1) | (read(x, y) ^ Number(mask(x, y)));
          if (++bits === 8) {
            words.push(byte);
            byte = 0;
            bits = 0;
          }
        }
      }
      upwards = !upwards;
    }
    return words;
  }

  function multiply(a, b) {
    let product = 0;
    while (b) {
      if (b & 1) product ^= a;
      a <<= 1;
      if (a & 256) a ^= 0x11d;
      b >>= 1;
    }
    return product;
  }

  function deinterleave(words, count, parity) {
    const shortLength = Math.floor(words.length / count);
    const shortCount = count - words.length % count;
    const blocks = Array.from({length: count}, (_, index) =>
      new Uint8Array(shortLength + Number(index >= shortCount)));
    let offset = 0;
    for (let column = 0; column < blocks.at(-1).length - parity; column++) {
      for (const block of blocks) {
        if (column < block.length - parity) block[column] = words[offset++];
      }
    }
    for (let column = 0; column < parity; column++) {
      for (const block of blocks) block[block.length - parity + column] = words[offset++];
    }

    // Check the Reed–Solomon syndromes before trusting a decoded secret.
    const data = [];
    for (const block of blocks) {
      let root = 1;
      for (let column = 0; column < parity; column++) {
        let syndrome = 0;
        for (const byte of block) syndrome = multiply(syndrome, root) ^ byte;
        if (syndrome) return null;
        root = multiply(root, 2);
      }
      data.push(...block.subarray(0, block.length - parity));
    }
    return data;
  }

  function readPayload(data, version) {
    let offset = 0;
    function bits(length) {
      if (offset + length > data.length * 8) throw new RangeError("QR payload is truncated");
      let result = 0;
      for (let bit = 0; bit < length; bit++, offset++) {
        result = (result << 1) | ((data[offset >> 3] >> (7 - (offset % 8))) & 1);
      }
      return result;
    }
    const bytes = [];
    try {
      while (offset + 4 <= data.length * 8) {
        const mode = bits(4);
        if (mode === 0) break;
        if (mode === 7 && bits(8) === 26) continue; // UTF-8 ECI
        if (mode === 4) {
          const count = bits(version < 10 ? 8 : 16);
          for (let i = 0; i < count; i++) bytes.push(bits(8));
        } else if (mode === 2) {
          let count = bits(version < 10 ? 9 : 11);
          while (count >= 2) {
            const pair = bits(11);
            if (pair >= 45 * 45) return null;
            bytes.push(alphanumeric.charCodeAt(Math.floor(pair / 45)), alphanumeric.charCodeAt(pair % 45));
            count -= 2;
          }
          if (count) {
            const index = bits(6);
            if (index >= 45) return null;
            bytes.push(alphanumeric.charCodeAt(index));
          }
        } else if (mode === 1) {
          let count = bits(version < 10 ? 10 : 12);
          while (count) {
            const length = Math.min(3, count);
            const number = bits(3 * length + 1);
            if (number >= 10 ** length) return null;
            for (const digit of String(number).padStart(length, "0")) bytes.push(digit.charCodeAt(0));
            count -= length;
          }
        } else {
          return null;
        }
      }
      const value = new TextDecoder("utf-8", {fatal: true}).decode(Uint8Array.from(bytes));
      return /^otpauth:\/\/totp\//i.test(value) ? value : null;
    } catch {
      return null;
    }
  }

  return function decodeTotpQr({data, width, height}) {
    const pixels = new Uint8Array(width * height);
    let left = width, top = height, right = -1, bottom = -1;
    for (let y = 0; y < height; y++) {
      for (let x = 0; x < width; x++) {
        const index = y * width + x;
        const offset = index * 4;
        if (data[offset + 3] < 128 || data[offset] + data[offset + 1] + data[offset + 2] >= 384) continue;
        pixels[index] = 1;
        left = Math.min(left, x);
        right = Math.max(right, x);
        top = Math.min(top, y);
        bottom = Math.max(bottom, y);
      }
    }
    const spanX = right - left + 1;
    const spanY = bottom - top + 1;
    for (let version = 1; version <= blockCounts.length; version++) {
      const size = 17 + 4 * version;
      if (size > Math.min(spanX, spanY)) break;
      const matrix = new Uint8Array(size * size);
      for (let y = 0; y < size; y++) {
        const row = Math.floor(top + (y + 0.5) * spanY / size);
        for (let x = 0; x < size; x++) {
          matrix[y * size + x] = pixels[row * width + Math.floor(left + (x + 0.5) * spanX / size)];
        }
      }
      const last = size - 1;
      for (const read of [
        (x, y) => matrix[y * size + x],
        (x, y) => matrix[x * size + last - y],
        (x, y) => matrix[(last - y) * size + last - x],
        (x, y) => matrix[(last - x) * size + y],
      ]) {
        if (!finderMatches(read, 0, 0) || !finderMatches(read, size - 7, 0) ||
            !finderMatches(read, 0, size - 7)) continue;
        const format = readFormat(read, size);
        if (format < 0) continue;
        const level = format >> 3;
        const mask = masks[format & 7];
        const words = readCodewords(read, size, version, mask);
        const decoded = deinterleave(words, blockCounts[version - 1][level], parityLengths[version - 1][level]);
        const value = decoded && readPayload(decoded, version);
        if (value) return value;
      }
    }
    return null;
  };
})();
