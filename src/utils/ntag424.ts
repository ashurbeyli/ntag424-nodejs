import * as crypto from 'crypto';
import { UidAndCounter, SdmSessionVectorOptions } from '../types';
import { calculateCmac } from './crypto';

/**
 * Decrypt PICC data using AES-ECB with SDM key
 * @param piccData - The encrypted PICC data (16 bytes)
 * @param sdmKey - The SDM Meta Read Key (16 bytes)
 * @returns Decrypted data or null if failed
 */
export function decryptPiccData(piccData: Buffer, sdmKey: Buffer): Buffer | null {
  try {
    const decipher = crypto.createDecipheriv('aes-128-ecb', sdmKey, null);
    decipher.setAutoPadding(false);
    
    const decrypted = Buffer.concat([
      decipher.update(piccData),
      decipher.final()
    ]);
    
    return decrypted;
  } catch (error) {
    console.error('PICC data decryption failed:', (error as Error).message);
    return null;
  }
}

/**
 * Extract UID and counter from decrypted PICC data
 * @param decrypted - Decrypted PICC data
 * @returns Object containing UID and counter data or null if failed
 */
export function extractUidAndCounter(decrypted: Buffer): UidAndCounter | null {
  if (!decrypted || decrypted.length < 10) {
    return null;
  }
  
  let decryptedUid: Buffer;
  let decryptedCounter: Buffer;
  
  if (decrypted.length >= 11) {
    // Format: PICCDataTag (1 byte) + UID (7 bytes) + Counter (3 bytes) + Random (...)
    decryptedUid = decrypted.slice(1, 8);
    decryptedCounter = decrypted.slice(8, 11);
  } else if (decrypted.length >= 10) {
    // Format: UID (7 bytes) + Counter (3 bytes) + Random (...)
    decryptedUid = decrypted.slice(0, 7);
    decryptedCounter = decrypted.slice(7, 10);
  } else {
    return null;
  }
  
  const decryptedUidHex = decryptedUid.toString('hex').toUpperCase();
  const decryptedCounterInt = decryptedCounter.readUIntLE(0, 3);
  
  return {
    uid: decryptedUid,
    counter: decryptedCounter,
    uidHex: decryptedUidHex,
    counterInt: decryptedCounterInt
  };
}

/**
 * Generate SDM session vector for key derivation
 * @param purpose - Purpose bytes (e.g., 0x3C, 0xC3 for MAC key)
 * @param uid - UID (7 bytes)
 * @param readCtr - Read counter (3-byte integer)
 * @param options - Options for UID mirroring and read counter inclusion
 * @returns Session vector
 */
export function generateSdmSessionVector(
  purpose: Buffer,
  uid: Buffer,
  readCtr: number,
  options: SdmSessionVectorOptions = { uidMirroring: true, readCounter: true }
): Buffer {
  const { uidMirroring = true, readCounter = true } = options;
  
  // read_ctr is a 3-byte counter, little-endian on the wire
  const rc = Buffer.alloc(3);
  rc.writeUIntBE(readCtr, 0, 3);
  rc.reverse(); // Convert to little-endian
  
  let vec = Buffer.concat([purpose, Buffer.from([0x00, 0x01, 0x00, 0x80])]);
  
  // SESSION_ENCRYPTION_KEY_PURPOSE (0xC3, 0x3C) always includes UID + readCtr
  if (purpose.equals(Buffer.from([0xC3, 0x3C]))) {
    vec = Buffer.concat([vec, uid, rc]);
  }
  // SESSION_MAC_KEY_PURPOSE (0x3C, 0xC3) conditionally includes based on settings
  else if (purpose.equals(Buffer.from([0x3C, 0xC3]))) {
    if (uidMirroring) {
      vec = Buffer.concat([vec, uid]);
    }
    if (readCounter) {
      vec = Buffer.concat([vec, rc]);
    }
  }
  
  return vec;
}

/**
 * Generate SDM session key
 * @param fileReadKey - The file read key (SDM key)
 * @param purpose - Purpose bytes
 * @param uid - UID (7 bytes)
 * @param readCtr - Read counter
 * @param options - Options for UID mirroring and read counter inclusion
 * @returns Session key
 */
export function generateSdmSessionKey(
  fileReadKey: Buffer,
  purpose: Buffer,
  uid: Buffer,
  readCtr: number,
  options: SdmSessionVectorOptions = { uidMirroring: true, readCounter: true }
): Buffer {
  const sessionVector = generateSdmSessionVector(purpose, uid, readCtr, options);
  
  if (sessionVector.length < 16) {
    const padding = Buffer.alloc(16 - sessionVector.length);
    return calculateCmac(fileReadKey, Buffer.concat([sessionVector, padding]));
  }
  
  return calculateCmac(fileReadKey, sessionVector);
}
