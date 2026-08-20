'use strict';

const IMSW_MAGIC = Buffer.from('IMSW');
const IMSW_HEADER_BYTES = 40;

/** Extract the state anchor without parsing the large payload body. */
function extractSlimAnchor(header) {
  if (!Buffer.isBuffer(header)) header = Buffer.from(header);
  if (header.length >= 4 && header.subarray(0, 4).equals(IMSW_MAGIC)) {
    if (header.length < IMSW_HEADER_BYTES) throw new Error('truncated IMSW header');
    if (header[4] !== 1 || !header.subarray(5, 8).equals(Buffer.alloc(3))) {
      throw new Error('unsupported or non-canonical IMSW header');
    }
    return '0x' + header.subarray(8, IMSW_HEADER_BYTES).toString('hex');
  }
  const match = /"anchorDigest"\s*:\s*"([^"]+)"/.exec(String(header));
  if (match) return match[1];
  throw new Error('anchorDigest not found in IMSW/legacy-JSON header (SlimSendPayload required)');
}

module.exports = { IMSW_HEADER_BYTES, extractSlimAnchor };
