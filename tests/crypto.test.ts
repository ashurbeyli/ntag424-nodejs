import { xor, shiftLeft, generateSubkeys, calculateCmac, truncateCmac } from '../src/utils/crypto';

describe('Crypto Utilities', () => {
  describe('xor', () => {
    it('should XOR two equal-length buffers', () => {
      const buf1 = Buffer.from([0x01, 0x02, 0x03]);
      const buf2 = Buffer.from([0x04, 0x05, 0x06]);
      const result = xor(buf1, buf2);
      expect(result).toEqual(Buffer.from([0x05, 0x07, 0x05]));
    });

    it('should XOR buffers of different lengths', () => {
      const buf1 = Buffer.from([0x01, 0x02]);
      const buf2 = Buffer.from([0x04, 0x05, 0x06]);
      const result = xor(buf1, buf2);
      expect(result).toEqual(Buffer.from([0x05, 0x07, 0x06]));
    });

    it('should handle empty buffers', () => {
      const buf1 = Buffer.alloc(0);
      const buf2 = Buffer.from([0x01, 0x02]);
      const result = xor(buf1, buf2);
      expect(result).toEqual(Buffer.from([0x01, 0x02]));
    });
  });

  describe('shiftLeft', () => {
    it('should shift buffer left by one bit', () => {
      const buffer = Buffer.from([0x80, 0x01, 0x02]);
      const result = shiftLeft(buffer);
      expect(result).toEqual(Buffer.from([0x00, 0x02, 0x04]));
    });

    it('should handle overflow correctly', () => {
      const buffer = Buffer.from([0xFF, 0x80]);
      const result = shiftLeft(buffer);
      expect(result).toEqual(Buffer.from([0xFF, 0x00]));
    });

    it('should handle empty buffer', () => {
      const buffer = Buffer.alloc(0);
      const result = shiftLeft(buffer);
      expect(result).toEqual(Buffer.alloc(0));
    });
  });

  describe('generateSubkeys', () => {
    it('should generate valid subkeys', () => {
      const key = Buffer.from('00000000000000000000000000000000', 'hex');
      const { k1, k2 } = generateSubkeys(key);
      
      expect(k1).toHaveLength(16);
      expect(k2).toHaveLength(16);
      expect(k1).not.toEqual(k2);
    });

    it('should generate consistent subkeys for same key', () => {
      const key = Buffer.from('00000000000000000000000000000000', 'hex');
      const { k1: k1a, k2: k2a } = generateSubkeys(key);
      const { k1: k1b, k2: k2b } = generateSubkeys(key);
      
      expect(k1a).toEqual(k1b);
      expect(k2a).toEqual(k2b);
    });
  });

  describe('calculateCmac', () => {
    it('should calculate CMAC for empty data', () => {
      const key = Buffer.from('00000000000000000000000000000000', 'hex');
      const data = Buffer.alloc(0);
      const cmac = calculateCmac(key, data);
      
      expect(cmac).toHaveLength(16);
    });

    it('should calculate CMAC for single block data', () => {
      const key = Buffer.from('00000000000000000000000000000000', 'hex');
      const data = Buffer.from('1234567890ABCDEF1234567890ABCDEF', 'hex');
      const cmac = calculateCmac(key, data);
      
      expect(cmac).toHaveLength(16);
    });

    it('should calculate CMAC for multi-block data', () => {
      const key = Buffer.from('00000000000000000000000000000000', 'hex');
      const data = Buffer.from('1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF', 'hex');
      const cmac = calculateCmac(key, data);
      
      expect(cmac).toHaveLength(16);
    });
  });

  describe('truncateCmac', () => {
    it('should truncate CMAC to 8 bytes', () => {
      const cmac = Buffer.from('1234567890ABCDEF1234567890ABCDEF', 'hex');
      const truncated = truncateCmac(cmac);
      
      expect(truncated).toHaveLength(8);
      expect(truncated).toEqual(Buffer.from('3478ABEF3478ABEF', 'hex'));
    });

    it('should handle 16-byte CMAC', () => {
      const cmac = Buffer.alloc(16, 0xFF);
      const truncated = truncateCmac(cmac);
      
      expect(truncated).toHaveLength(8);
      expect(truncated).toEqual(Buffer.alloc(8, 0xFF));
    });
  });
});
