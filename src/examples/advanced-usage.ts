#!/usr/bin/env node

import { 
  verifySdmAuth, 
  decryptPiccData, 
  extractUidAndCounter, 
  generateSdmSessionKey,
  calculateCmac,
  truncateCmac
} from '../index';

/**
 * Advanced usage example showing individual functions
 */

const sdmKey = Buffer.from('00000000000000000000000000000000', 'hex');
const piccDataHex = '1234567890ABCDEF1234567890ABCDEF';
const providedCmacHex = '1234567890ABCDEF';

console.log('NTAG424 Advanced Usage Example');
console.log('==============================');
console.log();

// Step 1: Decrypt PICC data
console.log('Step 1: Decrypt PICC Data');
console.log('-------------------------');
const piccData = Buffer.from(piccDataHex, 'hex');
const decrypted = decryptPiccData(piccData, sdmKey);

if (decrypted) {
  console.log(`✓ PICC data decrypted successfully`);
  console.log(`  Decrypted: ${decrypted.toString('hex').toUpperCase()}`);
} else {
  console.log('✗ PICC data decryption failed');
  process.exit(1);
}
console.log();

// Step 2: Extract UID and counter
console.log('Step 2: Extract UID and Counter');
console.log('-------------------------------');
const uidAndCounter = extractUidAndCounter(decrypted);

if (uidAndCounter) {
  console.log(`✓ UID and counter extracted successfully`);
  console.log(`  UID: ${uidAndCounter.uidHex}`);
  console.log(`  Counter: ${uidAndCounter.counterInt} (0x${uidAndCounter.counterInt.toString(16).toUpperCase()})`);
} else {
  console.log('✗ Failed to extract UID and counter');
  process.exit(1);
}
console.log();

// Step 3: Generate session key
console.log('Step 3: Generate Session Key');
console.log('----------------------------');
const SESSION_MAC_KEY_PURPOSE = Buffer.from([0x3C, 0xC3]);
const sessionMacKey = generateSdmSessionKey(
  sdmKey,
  SESSION_MAC_KEY_PURPOSE,
  uidAndCounter.uid,
  uidAndCounter.counterInt,
  { uidMirroring: true, readCounter: true }
);

console.log(`✓ Session MAC key generated`);
console.log(`  Session Key: ${sessionMacKey.toString('hex').toUpperCase()}`);
console.log();

// Step 4: Calculate CMAC
console.log('Step 4: Calculate CMAC');
console.log('----------------------');
const fullCmac = calculateCmac(sessionMacKey, Buffer.alloc(0));
const truncatedCmac = truncateCmac(fullCmac);
const calculatedCmac = truncatedCmac.toString('hex').toUpperCase();

console.log(`✓ CMAC calculated`);
console.log(`  Full CMAC: ${fullCmac.toString('hex').toUpperCase()}`);
console.log(`  Truncated: ${calculatedCmac}`);
console.log();

// Step 5: Verify authentication
console.log('Step 5: Verify Authentication');
console.log('-----------------------------');
const providedCmac = providedCmacHex.toUpperCase();
const isValid = calculatedCmac === providedCmac;

console.log(`Provided CMAC: ${providedCmac}`);
console.log(`Calculated:    ${calculatedCmac}`);
console.log(`Match: ${isValid ? '✓ Valid' : '✗ Invalid'}`);
console.log();

// Compare with high-level function
console.log('High-level Function Comparison');
console.log('------------------------------');
const highLevelResult = verifySdmAuth(piccDataHex, providedCmacHex, sdmKey.toString('hex'));

console.log(`High-level result: ${highLevelResult.success ? '✓ Valid' : '✗ Invalid'}`);
console.log(`UID: ${highLevelResult.uid}`);
console.log(`Counter: ${highLevelResult.counter}`);
console.log(`Method: ${highLevelResult.method}`);
