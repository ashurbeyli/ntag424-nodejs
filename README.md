# ntag424-nodejs

[![npm version](https://badge.fury.io/js/ntag424-nodejs.svg)](https://badge.fury.io/js/ntag424-nodejs)
[![Build Status](https://github.com/yourusername/ntag424-nodejs/workflows/CI/badge.svg)](https://github.com/yourusername/ntag424-nodejs/actions)
[![Coverage Status](https://codecov.io/gh/yourusername/ntag424-nodejs/branch/main/graph/badge.svg)](https://codecov.io/gh/yourusername/ntag424-nodejs)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive Node.js library for NTAG424 SDM (Secure Dynamic Messaging) authentication and data verification. This library provides tools to verify PICC data and CMAC authentication for NTAG424 NFC tags.

## Features

- 🔐 **SDM Authentication**: Verify PICC data and CMAC for NTAG424 tags
- 🛡️ **Type Safety**: Full TypeScript support with comprehensive type definitions
- 🧪 **Well Tested**: Comprehensive test suite with high coverage
- 🚀 **CLI Tool**: Command-line interface for easy integration
- 📚 **Documentation**: Detailed API documentation and examples
- 🔧 **Modular**: Use individual functions or the complete authentication flow

## Installation

```bash
npm install ntag424-nodejs
```

## Quick Start

### Basic Usage

```typescript
import { verifySdmAuth } from 'ntag424-nodejs';

// Set your SDM key (32-character hex string)
process.env.NTAG424_SDM_KEY = '00000000000000000000000000000000';

// Verify authentication
const result = verifySdmAuth(
  '1234567890ABCDEF1234567890ABCDEF', // PICC data
  '1234567890ABCDEF'                  // CMAC
);

if (result.success) {
  console.log('Authentication successful!');
  console.log(`UID: ${result.uid}`);
  console.log(`Counter: ${result.counter}`);
} else {
  console.log('Authentication failed:', result.error);
}
```

### CLI Usage

```bash
# Install globally
npm install -g ntag424-nodejs

# Verify authentication
ntag424-cli -p 1234567890ABCDEF1234567890ABCDEF -c 1234567890ABCDEF

# With verbose output
ntag424-cli --picc-data 1234567890ABCDEF1234567890ABCDEF --cmac 1234567890ABCDEF --verbose

# Using environment variable for SDM key
NTAG424_SDM_KEY=00000000000000000000000000000000 ntag424-cli -p 1234567890ABCDEF1234567890ABCDEF -c 1234567890ABCDEF
```

## API Reference

### Main Functions

#### `verifySdmAuth(piccDataHex, providedCmacHex, sdmKeyHex?)`

Verifies SDM authentication for NTAG424 tags.

**Parameters:**
- `piccDataHex` (string): PICC data as hex string
- `providedCmacHex` (string): Provided CMAC as hex string
- `sdmKeyHex` (string, optional): SDM key as hex string. If not provided, uses `NTAG424_SDM_KEY` environment variable

**Returns:** `SdmAuthResult`
```typescript
interface SdmAuthResult {
  success: boolean;
  uid?: string;
  counter?: number;
  method?: string;
  calculatedCmac?: string;
  providedCmac?: string;
  error?: string;
}
```

### Utility Functions

#### `decryptPiccData(piccData, sdmKey)`
Decrypts PICC data using AES-ECB with SDM key.

#### `extractUidAndCounter(decrypted)`
Extracts UID and counter from decrypted PICC data.

#### `generateSdmSessionKey(fileReadKey, purpose, uid, readCtr, options?)`
Generates SDM session key for authentication.

#### `calculateCmac(key, data)`
Calculates CMAC using AES-128.

#### `truncateCmac(cmac)`
Truncates CMAC to 8 bytes.

## Advanced Usage

### Using Individual Functions

```typescript
import { 
  decryptPiccData, 
  extractUidAndCounter, 
  generateSdmSessionKey,
  calculateCmac,
  truncateCmac 
} from 'ntag424-nodejs';

const sdmKey = Buffer.from('00000000000000000000000000000000', 'hex');
const piccData = Buffer.from('1234567890ABCDEF1234567890ABCDEF', 'hex');

// Step 1: Decrypt PICC data
const decrypted = decryptPiccData(piccData, sdmKey);

// Step 2: Extract UID and counter
const uidAndCounter = extractUidAndCounter(decrypted);

// Step 3: Generate session key
const sessionKey = generateSdmSessionKey(
  sdmKey,
  Buffer.from([0x3C, 0xC3]), // SESSION_MAC_KEY_PURPOSE
  uidAndCounter.uid,
  uidAndCounter.counterInt
);

// Step 4: Calculate CMAC
const fullCmac = calculateCmac(sessionKey, Buffer.alloc(0));
const truncatedCmac = truncateCmac(fullCmac);
```

### Custom Session Vector Options

```typescript
import { generateSdmSessionKey } from 'ntag424-nodejs';

const sessionKey = generateSdmSessionKey(
  sdmKey,
  purpose,
  uid,
  readCtr,
  {
    uidMirroring: true,  // Include UID in session vector
    readCounter: true    // Include read counter in session vector
  }
);
```

## Configuration

### Environment Variables

- `NTAG424_SDM_KEY`: Default SDM key (32-character hex string)

### CSV Configuration

The repository includes a sample CSV file (`mezi_local_mac_mirroring.csv`) for configuring NTAG424 tags. Key points:

1. **SDM_KEY**: Default key is `00000000000000000000000000000000`
2. **Offsets**: Ensure correct offsets for `piccData`, `macInput`, and `mac` in the CSV file
3. **macInput offset**: Should equal the `mac` offset

## Development

### Prerequisites

- Node.js 14.x or higher
- npm or yarn

### Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/ntag424-nodejs.git
cd ntag424-nodejs

# Install dependencies
npm install

# Build the project
npm run build

# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Run linter
npm run lint

# Format code
npm run format
```

### Scripts

- `npm run build` - Build TypeScript to JavaScript
- `npm run dev` - Build in watch mode
- `npm test` - Run tests
- `npm run test:watch` - Run tests in watch mode
- `npm run test:coverage` - Run tests with coverage
- `npm run lint` - Run ESLint
- `npm run lint:fix` - Fix ESLint issues
- `npm run format` - Format code with Prettier
- `npm run example` - Run basic usage example
- `npm run cli` - Run CLI tool

## Examples

### Basic Authentication

```typescript
import { verifySdmAuth } from 'ntag424-nodejs';

const result = verifySdmAuth(
  '1234567890ABCDEF1234567890ABCDEF',
  '1234567890ABCDEF',
  '00000000000000000000000000000000'
);

console.log(result);
```

### Error Handling

```typescript
import { verifySdmAuth } from 'ntag424-nodejs';

try {
  const result = verifySdmAuth(piccData, cmac);
  
  if (!result.success) {
    console.error('Authentication failed:', result.error);
    return;
  }
  
  // Process successful authentication
  console.log('UID:', result.uid);
  console.log('Counter:', result.counter);
} catch (error) {
  console.error('Unexpected error:', error);
}
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow the existing code style
- Add tests for new features
- Update documentation as needed
- Ensure all tests pass
- Run linting before committing

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Based on the NTAG424 DNA specification
- CMAC implementation follows GoToTags methodology
- Inspired by the need for reliable NTAG424 authentication in Node.js applications

## Support

- 📖 [Documentation](https://github.com/yourusername/ntag424-nodejs#readme)
- 🐛 [Issue Tracker](https://github.com/yourusername/ntag424-nodejs/issues)
- 💬 [Discussions](https://github.com/yourusername/ntag424-nodejs/discussions)

## Changelog

### v1.0.0
- Initial release
- SDM authentication functionality
- TypeScript support
- CLI tool
- Comprehensive test suite
- GitHub Actions CI/CD