/**
 * Type definitions for NTAG424 SDM authentication
 */

export interface UidAndCounter {
  uid: Buffer;
  counter: Buffer;
  uidHex: string;
  counterInt: number;
}

export interface SdmAuthResult {
  success: boolean;
  uid?: string;
  counter?: number;
  method?: string | null;
  calculatedCmac?: string;
  providedCmac?: string;
  error?: string;
}

export interface SdmSessionVectorOptions {
  uidMirroring?: boolean;
  readCounter?: boolean;
}

export interface Subkeys {
  k1: Buffer;
  k2: Buffer;
}

export type PurposeBytes = Buffer;
