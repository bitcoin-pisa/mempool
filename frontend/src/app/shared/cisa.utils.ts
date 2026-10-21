import { TransactionFlags } from '@app/shared/filters.utils';
import type { Transaction, Vin } from '@interfaces/electrs.interface';

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

/** Inputs that share one aggregate signature. */
export interface CisaGroup {
  mode: 'full' | 'half';
  /** input indexes of the group, in transaction order */
  inputs: number[];
  /** the input whose witness carries the aggregate: the group's last */
  carrier: number;
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

function parsedCisa(vin: Vin): ParsedCisa | null {
  if (vin.prevout?.scriptpubkey_type !== CISA_SCRIPT_TYPE) {
    return null;
  }
  return vin.cisaInfo ?? parseCisa(vin.witness);
}

/**
 * The aggregation groups of a transaction. BIP 460 has at most one group per
 * mode, and the group's final input, the one carrying the aggregate, is its
 * last member in input order.
 */
export function cisaGroups(vins: Vin[]): CisaGroup[] {
  const groups: CisaGroup[] = [];
  for (const mode of ['full', 'half'] as const) {
    const inputs: number[] = [];
    let carrier: number | null = null;
    vins.forEach((vin, index) => {
      const role = parsedCisa(vin)?.role;
      if (role === `${mode}agg_member`) {
        inputs.push(index);
      } else if (role === `${mode}agg_final`) {
        inputs.push(index);
        carrier = index;
      }
    });
    if (carrier !== null && inputs.length) {
      groups.push({ mode, inputs, carrier });
    }
  }
  return groups;
}

function elementBytes(vin: Vin, info: ParsedCisa): number {
  return (vin.witness?.[info.elementIndex]?.length ?? 0) / 2;
}

/** A BIP 340 signature, with its sighash byte unless that is SIGHASH_DEFAULT. */
function plainSignatureBytes(info: ParsedCisa): number {
  return info.sighash ? 65 : 64;
}

export interface CisaInputCost {
  index: number;
  role: CisaRole;
  /** bytes of the signature element as the transaction carries it */
  bytes: number;
  /** bytes the element would take as an ordinary signature of its own */
  plainBytes: number;
  group?: CisaGroup;
}

/** What aggregation saved this transaction, against signing every input on its own. */
export interface CisaSavings {
  inputs: CisaInputCost[];
  groups: CisaGroup[];
  /** signatures the CISA inputs carry: one per group, one per opted-out input */
  signatures: number;
  /** signatures they would carry with every input signed on its own */
  signaturesWithout: number;
  savedWu: number;
  weight: number;
  weightWithout: number;
  vsize: number;
  vsizeWithout: number;
  savedVb: number;
  /** share of the unaggregated size saved, in percent */
  percent: number;
  /** sat/vB the transaction pays */
  feeRate: number;
  /** what the saved weight is worth at that fee rate, in sats */
  feeSaved: number;
}

/**
 * Compare the transaction with the same transaction where every CISA input
 * carries its own signature. Witness bytes weigh one weight unit each, and
 * every element here is shorter than 253 bytes, so its length prefix is one
 * byte either way and only the element itself differs. A full aggregation
 * member saves its whole 64-byte signature; the group's final input pays one
 * marker byte more than a plain signature.
 */
export function cisaSavings(tx: Transaction): CisaSavings | null {
  if (!tx?.vin?.length || !tx.weight) {
    return null;
  }
  const groups = cisaGroups(tx.vin);
  if (!groups.length) {
    return null;
  }
  const inGroup = new Map<number, CisaGroup>();
  groups.forEach((group) => group.inputs.forEach((index) => inGroup.set(index, group)));
  const inputs: CisaInputCost[] = [];
  tx.vin.forEach((vin, index) => {
    const info = parsedCisa(vin);
    if (!info || info.role === 'invalid') {
      return;
    }
    inputs.push({
      index,
      role: info.role,
      bytes: elementBytes(vin, info),
      plainBytes: plainSignatureBytes(info),
      group: inGroup.get(index),
    });
  });
  const savedWu = inputs.reduce((sum, input) => sum + input.plainBytes - input.bytes, 0);
  const weight = tx.weight;
  const weightWithout = weight + savedWu;
  const vsize = Math.ceil(weight / 4);
  const vsizeWithout = Math.ceil(weightWithout / 4);
  const feeRate = tx.fee ? tx.fee / (weight / 4) : 0;
  return {
    inputs,
    groups,
    signatures: inputs.filter((input) => input.role === 'opted_out').length + groups.length,
    signaturesWithout: inputs.length,
    savedWu,
    weight,
    weightWithout,
    vsize,
    vsizeWithout,
    savedVb: vsizeWithout - vsize,
    percent: (savedWu / weightWithout) * 100,
    feeRate,
    feeSaved: Math.round((savedWu / 4) * feeRate),
  };
}
