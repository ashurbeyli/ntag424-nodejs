# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release preparation

## [1.0.0] - 2024-01-XX

### Added
- Initial release of ntag424-nodejs library
- SDM authentication functionality for NTAG424 tags
- TypeScript support with comprehensive type definitions
- CLI tool for command-line authentication verification
- Comprehensive test suite with Jest
- GitHub Actions CI/CD pipeline
- ESLint and Prettier configuration
- MIT license
- Detailed documentation and examples

### Features
- `verifySdmAuth()` - Main authentication function
- `decryptPiccData()` - PICC data decryption
- `extractUidAndCounter()` - UID and counter extraction
- `generateSdmSessionKey()` - Session key generation
- `calculateCmac()` - CMAC calculation
- `truncateCmac()` - CMAC truncation
- Support for environment variable configuration
- Modular architecture for advanced usage

### Technical Details
- Built with TypeScript for type safety
- Uses Node.js crypto module for AES operations
- Implements CMAC according to GoToTags methodology
- Supports both programmatic and CLI usage
- Comprehensive error handling and validation
