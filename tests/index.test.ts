import { verifySdmAuth } from '../src/index';

describe('SDM Authentication', () => {
  const testSdmKey = '00000000000000000000000000000000';
  
  beforeEach(() => {
    // Set test environment variable
    process.env['NTAG424_SDM_KEY'] = testSdmKey;
  });

  afterEach(() => {
    // Clean up environment variable
    delete process.env['NTAG424_SDM_KEY'];
  });

  describe('verifySdmAuth', () => {
    it('should return error when SDM key is not configured', () => {
      delete process.env['NTAG424_SDM_KEY'];
      
      const result = verifySdmAuth('1234567890ABCDEF1234567890ABCDEF', '1234567890ABCDEF');
      
      expect(result.success).toBe(false);
      expect(result.error).toBe('SDM key not configured');
    });

    it('should accept SDM key as parameter', () => {
      delete process.env['NTAG424_SDM_KEY'];
      
      const result = verifySdmAuth(
        '1234567890ABCDEF1234567890ABCDEF', 
        '1234567890ABCDEF',
        testSdmKey
      );
      
      expect(result).toHaveProperty('success');
      expect(result).toHaveProperty('uid');
      expect(result).toHaveProperty('counter');
    });

    it('should handle invalid hex input gracefully', () => {
      const result = verifySdmAuth('invalid', 'invalid');
      
      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should handle decryption failures gracefully', () => {
      const result = verifySdmAuth('00000000000000000000000000000000', '1234567890ABCDEF', testSdmKey);
      
      expect(result.success).toBe(false);
      expect(result.calculatedCmac).toBeDefined();
      expect(result.providedCmac).toBeDefined();
    });

    it('should return proper structure for valid input', () => {
      const result = verifySdmAuth('1234567890ABCDEF1234567890ABCDEF', '1234567890ABCDEF');
      
      expect(result).toHaveProperty('success');
      expect(result).toHaveProperty('uid');
      expect(result).toHaveProperty('counter');
      expect(result).toHaveProperty('calculatedCmac');
      expect(result).toHaveProperty('providedCmac');
      
      if (result.success) {
        expect(result).toHaveProperty('method');
      }
    });

    it('should handle environment variable SDM key', () => {
      const result = verifySdmAuth('1234567890ABCDEF1234567890ABCDEF', '1234567890ABCDEF');
      
      expect(result).toHaveProperty('success');
      expect(result).toHaveProperty('calculatedCmac');
      expect(result).toHaveProperty('providedCmac');
    });

    it('should normalize provided CMAC to uppercase', () => {
      const result = verifySdmAuth('1234567890ABCDEF1234567890ABCDEF', '1234567890abcdef');
      
      expect(result.providedCmac).toBe('1234567890ABCDEF');
    });
  });
});
