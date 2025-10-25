import * as crypto from 'crypto';
import { Subkeys } from '../types';

/**
 * XOR two buffers
 * @param bytes1 - First buffer
 * @param bytes2 - Second buffer
 * @returns XOR result buffer
 */
export function xor(bytes1: Buffer, bytes2: Buffer): Buffer {
  const result = Buffer.alloc(Math.max(bytes1.length, bytes2.length));
  for (let i = 0; i < result.length; i++) {
    result[i] = (bytes1[i] || 0) ^ (bytes2[i] || 0);
  }
  return result;
}

/**
 * Left shift a buffer by one bit
 * @param buffer - Buffer to shift
 * @returns Shifted buffer
 */
export function shiftLeft(buffer: Buffer): Buffer {
  const result = Buffer.alloc(buffer.length);
  let overflow = 0;
  
  for (let i = buffer.length - 1; i >= 0; i--) {
    const byte = buffer[i];
    if (byte !== undefined) {
      result[i] = ((byte << 1) | overflow) & 0xFF;
      overflow = (byte & 0x80) >> 7;
    }
  }
  
  return result;
}

/**
 * Generate CMAC subkeys K1 and K2
 * @param key - AES key
 * @returns Object containing K1 and K2 subkeys
 */
export function generateSubkeys(key: Buffer): Subkeys {
  const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
  cipher.setAutoPadding(false);
  
  const l = Buffer.concat([cipher.update(Buffer.alloc(16)), cipher.final()]);
  
  // Generate K1
  let k1 = shiftLeft(l);
  if (l[0] !== undefined && (l[0] & 0x80)) {
    const rb = Buffer.alloc(16);
    rb[15] = 0x87;
    k1 = xor(k1, rb);
  }
  
  // Generate K2
  let k2 = shiftLeft(k1);
  if (k1[0] !== undefined && (k1[0] & 0x80)) {
    const rb = Buffer.alloc(16);
    rb[15] = 0x87;
    k2 = xor(k2, rb);
  }
  
  return { k1, k2 };
}

/**
 * Calculate CMAC using AES-128
 * @param key - AES key
 * @param data - Data to calculate CMAC for
 * @returns CMAC buffer
 */
export function calculateCmac(key: Buffer, data: Buffer): Buffer {
  const { k1, k2 } = generateSubkeys(key);
  const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
  cipher.setAutoPadding(false);
  
  const blockSize = 16;
  const n = data.length === 0 ? 1 : Math.ceil(data.length / blockSize);
  const lastBlockComplete = data.length !== 0 && (data.length % blockSize) === 0;
  
  const lastBlock = Buffer.alloc(blockSize);
  
  if (lastBlockComplete) {
    const startIndex = (n - 1) * blockSize;
    data.copy(lastBlock, 0, startIndex, startIndex + blockSize);
  } else {
    const startIndex = data.length === 0 ? 0 : (n - 1) * blockSize;
    const rem = data.length === 0 ? 0 : data.length - startIndex;
    
    if (rem > 0) {
      data.copy(lastBlock, 0, startIndex, startIndex + rem);
    }
    lastBlock[rem] = 0x80;
  }
  
  // XOR last block with K1 (if complete) or K2 (if padded)
  const subkey = lastBlockComplete ? k1 : k2;
  const mLast = xor(lastBlock, subkey);
  
  // Process all full blocks before the last (if any)
  let x = Buffer.alloc(blockSize);
  const fullBlocks = n - 1;
  
  for (let i = 0; i < fullBlocks; i++) {
    const block = data.slice(i * blockSize, (i + 1) * blockSize);
    const y = xor(x, block);
    const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
    cipher.setAutoPadding(false);
    x = Buffer.concat([cipher.update(y), cipher.final()]);
  }
  
  // Final
  const y = xor(x, mLast);
  const finalCipher = crypto.createCipheriv('aes-128-ecb', key, null);
  finalCipher.setAutoPadding(false);
  return Buffer.concat([finalCipher.update(y), finalCipher.final()]);
}

/**
 * Truncate CMAC to 8 bytes (every other byte)
 * @param cmac - Full CMAC buffer
 * @returns Truncated CMAC buffer
 */
export function truncateCmac(cmac: Buffer): Buffer {
  const result = Buffer.alloc(8);
  for (let i = 0; i < 8; i++) {
    const byte = cmac[i * 2 + 1];
    if (byte !== undefined) {
      result[i] = byte;
    }
  }
  return result;
}
