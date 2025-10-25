#!/usr/bin/env node

import { verifySdmAuth } from '../index';

/**
 * Basic usage example for NTAG424 SDM authentication
 */

// Example PICC data and CMAC (these are example values)
const examplePiccData = '1234567890ABCDEF1234567890ABCDEF';
const exampleCmac = '1234567890ABCDEF';

// Set SDM key via environment variable or pass directly
const sdmKey = process.env['NTAG424_SDM_KEY'] || '00000000000000000000000000000000';

console.log('NTAG424 SDM Authentication Example');
console.log('==================================');
console.log();

console.log('Input:');
console.log(`  PICC Data: ${examplePiccData}`);
console.log(`  CMAC:      ${exampleCmac}`);
console.log(`  SDM Key:   ${sdmKey}`);
console.log();

// Verify authentication
const result = verifySdmAuth(examplePiccData, exampleCmac, sdmKey);

console.log('Result:');
console.log(`  Success: ${result.success}`);
if (result.success) {
  console.log(`  UID: ${result.uid}`);
  console.log(`  Counter: ${result.counter}`);
  console.log(`  Method: ${result.method}`);
} else {
  console.log(`  Error: ${result.error}`);
}
console.log();

console.log('Calculated vs Provided CMAC:');
console.log(`  Calculated: ${result.calculatedCmac}`);
console.log(`  Provided:   ${result.providedCmac}`);
console.log(`  Match:      ${result.calculatedCmac === result.providedCmac}`);
