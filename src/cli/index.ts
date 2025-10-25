#!/usr/bin/env node

import { verifySdmAuth } from '../index';

/**
 * CLI tool for NTAG424 SDM authentication
 */

interface CliOptions {
  piccData: string;
  cmac: string;
  sdmKey: string | undefined;
  verbose: boolean;
  help: boolean;
}

function parseArgs(): CliOptions {
  const args = process.argv.slice(2);
  const options: CliOptions = {
    piccData: '',
    cmac: '',
    sdmKey: undefined,
    verbose: false,
    help: false
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    
    switch (arg) {
      case '--picc-data':
      case '-p':
        options.piccData = args[++i] || '';
        break;
      case '--cmac':
      case '-c':
        options.cmac = args[++i] || '';
        break;
      case '--sdm-key':
      case '-k':
        options.sdmKey = args[++i];
        break;
      case '--verbose':
      case '-v':
        options.verbose = true;
        break;
      case '--help':
      case '-h':
        options.help = true;
        break;
      default:
        if (arg && arg.startsWith('-')) {
          console.error(`Unknown option: ${arg}`);
          process.exit(1);
        }
        break;
    }
  }

  return options;
}

function showHelp(): void {
  console.log(`
NTAG424 SDM Authentication CLI

Usage: ntag424-cli [options]

Options:
  -p, --picc-data <hex>    PICC data as hex string (required)
  -c, --cmac <hex>         CMAC as hex string (required)
  -k, --sdm-key <hex>      SDM key as hex string (optional, uses NTAG424_SDM_KEY env var)
  -v, --verbose            Show detailed output
  -h, --help               Show this help message

Environment Variables:
  NTAG424_SDM_KEY          Default SDM key (32-character hex string)

Examples:
  ntag424-cli -p 1234567890ABCDEF1234567890ABCDEF -c 1234567890ABCDEF
  ntag424-cli --picc-data 1234567890ABCDEF1234567890ABCDEF --cmac 1234567890ABCDEF --verbose
  NTAG424_SDM_KEY=00000000000000000000000000000000 ntag424-cli -p 1234567890ABCDEF1234567890ABCDEF -c 1234567890ABCDEF

Exit Codes:
  0  Authentication successful
  1  Authentication failed or error occurred
`);
}

function validateHexString(value: string, name: string): boolean {
  if (!/^[0-9A-Fa-f]+$/.test(value)) {
    console.error(`Error: ${name} must be a valid hex string`);
    return false;
  }
  return true;
}

function main(): void {
  const options = parseArgs();

  if (options.help) {
    showHelp();
    process.exit(0);
  }

  // Validate required arguments
  if (!options.piccData) {
    console.error('Error: --picc-data is required');
    console.error('Use --help for usage information');
    process.exit(1);
  }

  if (!options.cmac) {
    console.error('Error: --cmac is required');
    console.error('Use --help for usage information');
    process.exit(1);
  }

  // Validate hex strings
  if (!validateHexString(options.piccData, 'PICC data')) {
    process.exit(1);
  }

  if (!validateHexString(options.cmac, 'CMAC')) {
    process.exit(1);
  }

  if (options.sdmKey && !validateHexString(options.sdmKey, 'SDM key')) {
    process.exit(1);
  }

  // Check SDM key
  if (!options.sdmKey && !process.env['NTAG424_SDM_KEY']) {
    console.error('Error: SDM key not provided and NTAG424_SDM_KEY environment variable not set');
    console.error('Use --sdm-key option or set NTAG424_SDM_KEY environment variable');
    process.exit(1);
  }

  if (options.verbose) {
    console.log('NTAG424 SDM Authentication');
    console.log('==========================');
    console.log();
    console.log('Input:');
    console.log(`  PICC Data: ${options.piccData.toUpperCase()}`);
    console.log(`  CMAC:      ${options.cmac.toUpperCase()}`);
    console.log(`  SDM Key:   ${options.sdmKey || process.env['NTAG424_SDM_KEY'] || 'Not set'}`);
    console.log();
  }

  // Perform authentication
  const result = verifySdmAuth(options.piccData, options.cmac, options.sdmKey);

  if (options.verbose) {
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
    console.log('CMAC Comparison:');
    console.log(`  Calculated: ${result.calculatedCmac}`);
    console.log(`  Provided:   ${result.providedCmac}`);
    console.log(`  Match:      ${result.calculatedCmac === result.providedCmac}`);
  } else {
    // Simple output
    if (result.success) {
      console.log('✓ Authentication successful');
      console.log(`UID: ${result.uid}, Counter: ${result.counter}`);
    } else {
      console.log('✗ Authentication failed');
      console.log(`Error: ${result.error}`);
    }
  }

  process.exit(result.success ? 0 : 1);
}

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('Uncaught exception:', error.message);
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  console.error('Unhandled rejection:', reason);
  process.exit(1);
});

main();
