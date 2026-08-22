import { deepStrictEqual, strictEqual } from 'node:assert/strict';
import { describe, it } from 'node:test';
import { calculatePayjoinDetails, parsePayjoinOwnership } from './payjoin-ownership';

describe('Payjoin ownership', () => {
  it('parses ownership vectors that match the transaction', () => {
    deepStrictEqual(parsePayjoinOwnership('1:ssssssssr:rs', 9, 2), {
      inputs: [
        'sender', 'sender', 'sender', 'sender', 'sender',
        'sender', 'sender', 'sender', 'recipient',
      ],
      outputs: ['recipient', 'sender'],
    });
  });

  it('rejects malformed ownership vectors', () => {
    const invalidVectors: Array<[string | null, number, number]> = [
      [null, 2, 2],
      ['1:sr', 2, 2],
      ['2:sr:rs', 2, 2],
      ['1:sx:rs', 2, 2],
      ['1:sr:rs', 3, 2],
      ['1:sr:rs', 2, 1],
      ['1:ss:rs', 2, 2],
      ['1:rr:rs', 2, 2],
    ];

    for (const [value, inputCount, outputCount] of invalidVectors) {
      strictEqual(parsePayjoinOwnership(value, inputCount, outputCount), null);
    }
  });

  it('calculates the values displayed for both participants', () => {
    const ownership = parsePayjoinOwnership('1:ssr:rs', 3, 2)!;

    deepStrictEqual(
      calculatePayjoinDetails(
        [80_000, 30_000, 20_000],
        [70_000, 59_000],
        ownership,
      ),
      {
        senderInputValues: [
          { index: 0, value: 80_000 },
          { index: 1, value: 30_000 },
        ],
        recipientInputValues: [{ index: 2, value: 20_000 }],
        senderInputs: 110_000,
        recipientInputs: 20_000,
        senderOutputValues: [{ index: 1, value: 59_000 }],
        recipientOutputValues: [{ index: 0, value: 70_000 }],
        senderOutputs: 59_000,
        recipientOutputs: 70_000,
        fee: 1_000,
        senderNetDebit: 51_000,
        recipientNetGain: 50_000,
      },
    );
  });

  it('rejects incomplete or invalid calculations', () => {
    const ownership = parsePayjoinOwnership('1:sr:rs', 2, 2)!;
    const invalidValues: Array<[Array<number | null>, number[]]> = [
      [[80_000, null], [50_000, 49_000]],
      [[80_000, 50_000], [50_000, 79_000]],
      [[50_000, 20_000], [60_000, 20_000]],
    ];

    for (const [inputs, outputs] of invalidValues) {
      strictEqual(calculatePayjoinDetails(inputs, outputs, ownership), null);
    }
  });
});
