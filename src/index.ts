import { SdmAuthResult } from './types';
import { decryptPiccData, extractUidAndCounter, generateSdmSessionKey } from './utils/ntag424';
import { calculateCmac, truncateCmac } from './utils/crypto';

/**
 * Verify SDM authentication
 * @param piccDataHex - PICC data as hex string
 * @param providedCmacHex - Provided CMAC as hex string
 * @param sdmKeyHex - SDM key as hex string (optional, uses env var if not provided)
 * @returns Authentication result object
 */
export function verifySdmAuth(
  piccDataHex: string,
  providedCmacHex: string,
  sdmKeyHex?: string
): SdmAuthResult {
  try {
    // Get SDM key from environment variable if not provided
    if (!sdmKeyHex) {
      sdmKeyHex = process.env['NTAG424_SDM_KEY'];
      if (!sdmKeyHex) {
        return { success: false, error: 'SDM key not configured' };
      }
    }
    
    // Convert hex strings to buffers
    const piccData = Buffer.from(piccDataHex, 'hex');
    const providedCmac = providedCmacHex.toUpperCase();
    const sdmKey = Buffer.from(sdmKeyHex, 'hex');
    
    // Step 1: Decrypt PICC data
    const decrypted = decryptPiccData(piccData, sdmKey);
    if (!decrypted) {
      return { success: false, error: 'PICC data decryption failed' };
    }
    
    // Step 2: Extract UID and counter
    const cmacData = extractUidAndCounter(decrypted);
    if (!cmacData) {
      return { success: false, error: 'Failed to extract UID and counter' };
    }
    
    // Step 3: Calculate CMAC using the working method (Full mirroring with empty data)
    const SESSION_MAC_KEY_PURPOSE = Buffer.from([0x3C, 0xC3]);
    
    // Derive session MAC key with full mirroring
    const sessionMacKey = generateSdmSessionKey(
      sdmKey,
      SESSION_MAC_KEY_PURPOSE,
      cmacData.uid,
      cmacData.counterInt,
      { uidMirroring: true, readCounter: true }
    );
    
    // Calculate CMAC over empty data (the working method)
    const fullCmac = calculateCmac(sessionMacKey, Buffer.alloc(0));
    const truncCmac = truncateCmac(fullCmac);
    const calculatedCmac = truncCmac.toString('hex').toUpperCase();
    
    // Verify CMAC
    const isValid = calculatedCmac === providedCmac;
    
    return {
      success: isValid,
      uid: cmacData.uidHex,
      counter: cmacData.counterInt,
      method: isValid ? 'Full mirroring with empty data' : null,
      calculatedCmac: calculatedCmac,
      providedCmac: providedCmac
    };
    
  } catch (error) {
    console.error('SDM authentication error:', error);
    return { success: false, error: (error as Error).message };
  }
}

// Re-export all utilities and types for advanced usage
export { decryptPiccData, extractUidAndCounter, generateSdmSessionKey } from './utils/ntag424';
export { calculateCmac, truncateCmac, generateSubkeys, xor, shiftLeft } from './utils/crypto';
export * from './types';
