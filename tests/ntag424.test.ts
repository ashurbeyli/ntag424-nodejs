import { 
  decryptPiccData, 
  extractUidAndCounter, 
  generateSdmSessionVector, 
  generateSdmSessionKey 
} from '../src/utils/ntag424';

describe('NTAG424 Utilities', () => {
  describe('decryptPiccData', () => {
    it('should decrypt PICC data successfully', () => {
      const piccData = Buffer.from('1234567890ABCDEF1234567890ABCDEF', 'hex');
      const sdmKey = Buffer.from('00000000000000000000000000000000', 'hex');
      
      const result = decryptPiccData(piccData, sdmKey);
      expect(result).toBeInstanceOf(Buffer);
      expect(result).toHaveLength(16);
    });

    it('should return empty buffer for empty input', () => {
      const piccData = Buffer.alloc(0);
      const sdmKey = Buffer.from('00000000000000000000000000000000', 'hex');
      
      const result = decryptPiccData(piccData, sdmKey);
      expect(result).toEqual(Buffer.alloc(0));
    });

    it('should handle decryption errors gracefully', () => {
      const piccData = Buffer.from('1234567890ABCDEF1234567890ABCDEF', 'hex');
      const sdmKey = Buffer.from('00000000000000000000000000000000', 'hex');
      
      const result = decryptPiccData(piccData, sdmKey);
      expect(result).toBeInstanceOf(Buffer);
    });
  });

  describe('extractUidAndCounter', () => {
    it('should extract UID and counter from 11-byte data', () => {
      const decrypted = Buffer.from('041234567890ABCDEF123456', 'hex');
      const result = extractUidAndCounter(decrypted);
      
      expect(result).not.toBeNull();
      expect(result!.uidHex).toBe('1234567890ABCD');
      expect(result!.counterInt).toBe(0x3412EF);
    });

    it('should extract UID and counter from 10-byte data', () => {
      const decrypted = Buffer.from('1234567890ABCDEF123456', 'hex');
      const result = extractUidAndCounter(decrypted);
      
      expect(result).not.toBeNull();
      expect(result!.uidHex).toBe('34567890ABCDEF');
      expect(result!.counterInt).toBe(0x563412);
    });

    it('should return null for insufficient data', () => {
      const decrypted = Buffer.from('1234567890', 'hex');
      const result = extractUidAndCounter(decrypted);
      
      expect(result).toBeNull();
    });

    it('should return null for empty data', () => {
      const result = extractUidAndCounter(Buffer.alloc(0));
      expect(result).toBeNull();
    });
  });

  describe('generateSdmSessionVector', () => {
    const purpose = Buffer.from([0x3C, 0xC3]);
    const uid = Buffer.from('1234567890ABCDEF', 'hex');
    const readCtr = 0x123456;

    it('should generate session vector with default options', () => {
      const vector = generateSdmSessionVector(purpose, uid, readCtr);
      
      expect(vector).toBeInstanceOf(Buffer);
      expect(vector.length).toBeGreaterThan(0);
    });

    it('should generate session vector with custom options', () => {
      const vector = generateSdmSessionVector(purpose, uid, readCtr, {
        uidMirroring: false,
        readCounter: true
      });
      
      expect(vector).toBeInstanceOf(Buffer);
      expect(vector.length).toBeGreaterThan(0);
    });

    it('should handle encryption key purpose', () => {
      const encPurpose = Buffer.from([0xC3, 0x3C]);
      const vector = generateSdmSessionVector(encPurpose, uid, readCtr);
      
      expect(vector).toBeInstanceOf(Buffer);
      expect(vector.length).toBeGreaterThan(0);
    });
  });

  describe('generateSdmSessionKey', () => {
    const fileReadKey = Buffer.from('00000000000000000000000000000000', 'hex');
    const purpose = Buffer.from([0x3C, 0xC3]);
    const uid = Buffer.from('1234567890ABCDEF', 'hex');
    const readCtr = 0x123456;

    it('should generate session key with default options', () => {
      const sessionKey = generateSdmSessionKey(fileReadKey, purpose, uid, readCtr);
      
      expect(sessionKey).toBeInstanceOf(Buffer);
      expect(sessionKey).toHaveLength(16);
    });

    it('should generate session key with custom options', () => {
      const sessionKey = generateSdmSessionKey(fileReadKey, purpose, uid, readCtr, {
        uidMirroring: false,
        readCounter: true
      });
      
      expect(sessionKey).toBeInstanceOf(Buffer);
      expect(sessionKey).toHaveLength(16);
    });

    it('should generate consistent keys for same parameters', () => {
      const key1 = generateSdmSessionKey(fileReadKey, purpose, uid, readCtr);
      const key2 = generateSdmSessionKey(fileReadKey, purpose, uid, readCtr);
      
      expect(key1).toEqual(key2);
    });

    it('should generate different keys for different parameters', () => {
      const key1 = generateSdmSessionKey(fileReadKey, purpose, uid, readCtr);
      const key2 = generateSdmSessionKey(fileReadKey, purpose, uid, readCtr + 1);
      
      expect(key1).not.toEqual(key2);
    });
  });
});
