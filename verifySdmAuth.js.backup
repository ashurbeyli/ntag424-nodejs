const crypto = require('crypto');

/**
 * SDM Authentication Utility
 * Based on successful test-decrypt-piccdata.js implementation
 * 
 * This utility handles:
 * 1. Decrypting PICC data using SDM key from environment variable NTAG424_SDM_KEY
 * 2. Extracting UID and counter from decrypted data
 * 3. Calculating CMAC for authentication
 * 4. Verifying against provided CMAC
 * 
 * Environment Variables:
 * - NTAG424_SDM_KEY: 32-character hex string for SDM Meta Read Key (required)
 * 
 * Example usage:
 *   NTAG424_SDM_KEY=00000000000000000000000000000000
 */

/**
 * Decrypt PICC data using AES-ECB with SDM key
 * @param {Buffer} piccData - The encrypted PICC data (16 bytes)
 * @param {Buffer} sdmKey - The SDM Meta Read Key (16 bytes)
 * @returns {Buffer|null} - Decrypted data or null if failed
 */
function decryptPiccData(piccData, sdmKey) {
    try {
        const decipher = crypto.createDecipheriv('aes-128-ecb', sdmKey, null);
        decipher.setAutoPadding(false);
        
        const decrypted = Buffer.concat([
            decipher.update(piccData),
            decipher.final()
        ]);
        
        return decrypted;
    } catch (error) {
        console.error('PICC data decryption failed:', error.message);
        return null;
    }
}

/**
 * Extract UID and counter from decrypted PICC data
 * @param {Buffer} decrypted - Decrypted PICC data
 * @returns {Object|null} - {uid, counter, uidHex, counterInt} or null if failed
 */
function extractUidAndCounter(decrypted) {
    if (!decrypted || decrypted.length < 10) {
        return null;
    }
    
    let decryptedUid, decryptedCounter;
    
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
 * CMAC calculation functions (GoToTags implementation)
 */
function xor(bytes1, bytes2) {
    const result = Buffer.alloc(Math.max(bytes1.length, bytes2.length));
    for (let i = 0; i < result.length; i++) {
        result[i] = (bytes1[i] || 0) ^ (bytes2[i] || 0);
    }
    return result;
}

function shiftLeft(buffer) {
    const result = Buffer.alloc(buffer.length);
    let overflow = 0;
    
    for (let i = buffer.length - 1; i >= 0; i--) {
        result[i] = ((buffer[i] << 1) | overflow) & 0xFF;
        overflow = (buffer[i] & 0x80) >> 7;
    }
    
    return result;
}

function generateSubkeys(key) {
    const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
    cipher.setAutoPadding(false);
    
    const l = Buffer.concat([cipher.update(Buffer.alloc(16)), cipher.final()]);
    
    // Generate K1
    let k1 = shiftLeft(l);
    if (l[0] & 0x80) {
        const rb = Buffer.alloc(16);
        rb[15] = 0x87;
        k1 = xor(k1, rb);
    }
    
    // Generate K2
    let k2 = shiftLeft(k1);
    if (k1[0] & 0x80) {
        const rb = Buffer.alloc(16);
        rb[15] = 0x87;
        k2 = xor(k2, rb);
    }
    
    return { k1, k2 };
}

function calculateCmac(key, data) {
    const { k1, k2 } = generateSubkeys(key);
    const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
    cipher.setAutoPadding(false);
    
    const blockSize = 16;
    const n = data.length === 0 ? 1 : Math.ceil(data.length / blockSize);
    const lastBlockComplete = data.length !== 0 && (data.length % blockSize) === 0;
    
    let lastBlock = Buffer.alloc(blockSize);
    
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

function truncateCmac(cmac) {
    const result = Buffer.alloc(8);
    for (let i = 0; i < 8; i++) {
        result[i] = cmac[i * 2 + 1];
    }
    return result;
}

/**
 * Generate SDM session vector for key derivation
 * @param {Buffer} purpose - Purpose bytes (e.g., 0x3C, 0xC3 for MAC key)
 * @param {Buffer} uid - UID (7 bytes)
 * @param {number} readCtr - Read counter (3-byte integer)
 * @param {boolean} uidMirroring - Whether to include UID in vector
 * @param {boolean} readCounter - Whether to include counter in vector
 * @returns {Buffer} - Session vector
 */
function generateSdmSessionVector(purpose, uid, readCtr, uidMirroring = true, readCounter = true) {
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
 * @param {Buffer} fileReadKey - The file read key (SDM key)
 * @param {Buffer} purpose - Purpose bytes
 * @param {Buffer} uid - UID (7 bytes)
 * @param {number} readCtr - Read counter
 * @param {boolean} uidMirroring - Whether to include UID
 * @param {boolean} readCounter - Whether to include counter
 * @returns {Buffer} - Session key
 */
function generateSdmSessionKey(fileReadKey, purpose, uid, readCtr, uidMirroring = true, readCounter = true) {
    const sessionVector = generateSdmSessionVector(purpose, uid, readCtr, uidMirroring, readCounter);
    
    if (sessionVector.length < 16) {
        const padding = Buffer.alloc(16 - sessionVector.length);
        return calculateCmac(fileReadKey, Buffer.concat([sessionVector, padding]));
    }
    
    return calculateCmac(fileReadKey, sessionVector);
}

/**
 * Verify SDM authentication
 * @param {string} piccDataHex - PICC data as hex string
 * @param {string} providedCmacHex - Provided CMAC as hex string
 * @param {string} sdmKeyHex - SDM key as hex string (optional, uses env var if not provided)
 * @returns {Object} - {success: boolean, uid?: string, counter?: number, method?: string}
 */
function verifySdmAuth(piccDataHex, providedCmacHex, sdmKeyHex = null) {
    try {
        // Get SDM key from environment variable if not provided
        if (!sdmKeyHex) {
            sdmKeyHex = process.env.NTAG424_SDM_KEY;
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
            true,  // uidMirroring
            true   // readCounter
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
        return { success: false, error: error.message };
    }
}

module.exports = {
    verifySdmAuth,
    decryptPiccData,
    extractUidAndCounter,
    calculateCmac,
    generateSdmSessionKey
};
