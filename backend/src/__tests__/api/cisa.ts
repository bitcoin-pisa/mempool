import { Common } from '../../api/common';
import { TransactionFlags } from '../../mempool.interfaces';

const program = 'f63948033fb37de068df085b3e7fbe369e341671c473c8b7054491de7ae588c4';
const scriptpubkey = '5220' + program;

function cisaInput(witness: string[]): any {
  return {
    txid: '9f325ca668a7cd4d03a456cad5661de50f321518274c11897782cd08704fcbfe',
    vout: 0,
    scriptsig: '',
    scriptsig_asm: '',
    sequence: 0xfffffffd,
    witness,
    prevout: {
      scriptpubkey,
      scriptpubkey_asm: 'OP_PUSHNUM_2 OP_PUSHBYTES_32 ' + program,
      scriptpubkey_type: 'v2_p2cisa',
      scriptpubkey_address: 'bcrt1z7cu5sqelkd77q6xlppdnula7x60rg9n3c3eu3dc9gjgau7h93rzqa5ge3r',
      value: 1000000000,
    },
  };
}

/** A two-input full-aggregation group: an empty member witness and the final input. */
function fullaggTransaction(): any {
  return {
    txid: 'bf45a745b433203e7953d24c8d725a1a2fe50b00a78f8785b3ccdad4601ecd03',
    version: 2,
    locktime: 1,
    size: 258,
    weight: 783,
    fee: 352,
    vin: [cisaInput(['']), cisaInput(['a'.repeat(128) + 'bd'])],
    vout: [
      { scriptpubkey, scriptpubkey_asm: '', scriptpubkey_type: 'v2_p2cisa', scriptpubkey_address: 'bcrt1z7cu5sqelkd77q6xlppdnula7x60rg9n3c3eu3dc9gjgau7h93rzqa5ge3r', value: 1100000000 },
      { scriptpubkey, scriptpubkey_asm: '', scriptpubkey_type: 'v2_p2cisa', scriptpubkey_address: 'bcrt1zv6pwx44ad8u0xx0r05kwak63ystl0e9me5ky9jt32ure2ahyzhrq3he40d', value: 899999648 },
    ],
    status: { confirmed: true, block_height: 103 },
  };
}

describe('BIP 460 signature aggregation', () => {
  test('classifies the sighash type from the witness element by its length', () => {
    const def = TransactionFlags.sighash_default;
    const all = TransactionFlags.sighash_all;
    // full-aggregation member, half-aggregation member, opted out, finals
    expect(Common.setCisaSighashFlags(0n, [''])).toEqual(def);
    expect(Common.setCisaSighashFlags(0n, ['01'])).toEqual(all);
    expect(Common.setCisaSighashFlags(0n, ['b'.repeat(64)])).toEqual(def);
    expect(Common.setCisaSighashFlags(0n, ['b'.repeat(64) + '01'])).toEqual(all);
    expect(Common.setCisaSighashFlags(0n, ['c'.repeat(128)])).toEqual(def);
    expect(Common.setCisaSighashFlags(0n, ['c'.repeat(128) + '01'])).toEqual(all);
    expect(Common.setCisaSighashFlags(0n, ['c'.repeat(128) + 'bd'])).toEqual(def);
    expect(Common.setCisaSighashFlags(0n, ['c'.repeat(128) + '01bc'])).toEqual(all);
    // a 65-byte element ending in a valid sighash byte is an opted-out signature, not a final
    expect(Common.setCisaSighashFlags(0n, ['c'.repeat(128) + '83'])).toEqual(TransactionFlags.sighash_single | TransactionFlags.sighash_acp);
  });

  test('flags an aggregated transaction and does not call it non-standard', () => {
    const tx = fullaggTransaction();
    const flags = BigInt(Common.getTransactionFlags(tx));
    expect(flags & TransactionFlags.p2cisa).toBeTruthy();
    expect(flags & TransactionFlags.sighash_default).toBeTruthy();
    expect(flags & TransactionFlags.p2tr).toBeFalsy();
    expect(flags & TransactionFlags.nonstandard).toBeFalsy();
    expect(Common.isNonStandard(tx)).toEqual(false);
  });
});
