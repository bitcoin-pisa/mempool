import { TransactionFlags } from '@app/shared/filters.utils';

/**
 * BIP 460: cross-input signature aggregation for key path spends of a
 * dedicated witness version.
 *
 * The witness version is read from configuration because the BIP says it may
 * still change. Everything that depends on the version goes through this
 * module so that a change is a config edit, not a code change.
 */

export const CISA_SCRIPT_TYPE = 'v2_p2cisa';

const DEFAULT_WITNESS_VERSION = 2;

export function cisaWitnessVersion(): number {
  const configured = Number(window?.['__env']?.CISA_WITNESS_VERSION);
  return Number.isInteger(configured) && configured >= 1 && configured <= 16 ? configured : DEFAULT_WITNESS_VERSION;
}

/** OP_n for the witness version, followed by a 32-byte push. */
export function cisaScriptPubKeyRegex(): RegExp {
  const versionOpcode = (0x50 + cisaWitnessVersion()).toString(16);
  return new RegExp(`^${versionOpcode}20[0-9a-f]{64}$`);
}

export function cisaProgramFromScriptPubKey(scriptPubKey: string): string {
  return scriptPubKey.substring(4, 4 + 64);
}

const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

/** The first data character of a bech32m address encodes the witness version. */
export function cisaAddressLeadingChar(): string {
  return BECH32_CHARSET[cisaWitnessVersion()];
}

export type CisaRole = 'opted_out' | 'fullagg_member' | 'fullagg_final' | 'halfagg_member' | 'halfagg_final' | 'invalid';

export const CisaRoleLabels: Record<CisaRole, string> = {
  opted_out: 'Opted out of aggregation: plain Schnorr signature',
  fullagg_member: 'Full aggregation member: signature carried by the group\'s final input',
  fullagg_final: 'Full aggregation final input: the aggregate signature for the whole group',
  halfagg_member: 'Half aggregation member: nonce share only',
  halfagg_final: 'Half aggregation final input: nonce share and the aggregate s value',
  invalid: 'Not a valid BIP 460 witness element',
};

export interface ParsedCisa {
  role: CisaRole;
  /** index of the signature element in the witness stack */
  elementIndex: number;
  /** explicit sighash byte as hex, absent for SIGHASH_DEFAULT */
  sighash?: string;
  annex?: string;
  annexIndex?: number;
}

/**
 * Classify a key path witness of a CISA input. The single element's length
 * and last byte determine its role, see the witness structure table of
 * BIP 460. Lengths are in bytes here; the strings are hex.
 */
export function parseCisa(witness: string[]): ParsedCisa | null {
  if (!witness?.length) {
    return null;
  }
  const parsed: ParsedCisa = { role: 'invalid', elementIndex: 0 };
  if (witness.length > 1 && witness[witness.length - 1].startsWith('50')) {
    parsed.annexIndex = witness.length - 1;
    parsed.annex = witness[parsed.annexIndex];
  }
  if (witness.length > (parsed.annex ? 2 : 1)) {
    // script path spends are not aggregated
    return parsed;
  }
  const element = witness[0];
  const bytes = element.length / 2;
  const last = element.slice(-2);
  const isFinal = (bytes === 65 || bytes === 66) && (last === 'bc' || last === 'bd');
  const withoutMarker = isFinal ? element.slice(0, -2) : element;
  const dataBytes = withoutMarker.length / 2;

  if (isFinal) {
    parsed.role = last === 'bd' ? 'fullagg_final' : 'halfagg_final';
    if (dataBytes === 65) {
      parsed.sighash = withoutMarker.slice(-2);
    }
    return parsed;
  }
  switch (dataBytes) {
    case 64: parsed.role = 'opted_out'; break;
    case 65: parsed.role = 'opted_out'; parsed.sighash = last; break;
    case 0: parsed.role = 'fullagg_member'; break;
    case 1: parsed.role = 'fullagg_member'; parsed.sighash = last; break;
    case 32: parsed.role = 'halfagg_member'; break;
    case 33: parsed.role = 'halfagg_member'; parsed.sighash = last; break;
  }
  return parsed;
}

export function setCisaSighashFlags(flags: bigint, witness: string[]): bigint {
  const parsed = parseCisa(witness);
  if (!parsed || parsed.role === 'invalid') {
    return flags;
  }
  switch (parsed.sighash) {
    case undefined: return flags | TransactionFlags.sighash_default;
    case '01': return flags | TransactionFlags.sighash_all;
    case '02': return flags | TransactionFlags.sighash_none;
    case '03': return flags | TransactionFlags.sighash_single;
    case '81': return flags | TransactionFlags.sighash_all | TransactionFlags.sighash_acp;
    case '82': return flags | TransactionFlags.sighash_none | TransactionFlags.sighash_acp;
    case '83': return flags | TransactionFlags.sighash_single | TransactionFlags.sighash_acp;
    default: return flags;
  }
}
