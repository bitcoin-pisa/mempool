export type PayjoinOwner = 'sender' | 'recipient';

export interface PayjoinOwnership {
  inputs: PayjoinOwner[];
  outputs: PayjoinOwner[];
  /** names for the two parties, when the fragment gives them */
  labels: Record<PayjoinOwner, string | null>;
}

const MAX_LABEL_LENGTH = 24;

const DEFAULT_LABELS: Record<PayjoinOwner, string> = {
  sender: 'Sender',
  recipient: 'Recipient',
};

/** What to call a party: its name from the fragment, or its role. */
export function payjoinOwnerLabel(ownership: PayjoinOwnership | null, owner: PayjoinOwner): string {
  return ownership?.labels?.[owner] || DEFAULT_LABELS[owner];
}

/** A display name from the fragment, or null if it is empty or unusable. */
function parseLabel(value: string | undefined): string | null {
  // eslint-disable-next-line no-control-regex
  const label = value?.replace(/[\u0000-\u001f\u007f]/g, '').trim();
  return label ? label.slice(0, MAX_LABEL_LENGTH) : null;
}

interface PayjoinIndexedValue {
  index: number;
  value: number;
}

export interface PayjoinCalculation {
  senderInputValues: PayjoinIndexedValue[];
  recipientInputValues: PayjoinIndexedValue[];
  senderInputs: number;
  recipientInputs: number;
  senderOutputValues: PayjoinIndexedValue[];
  recipientOutputValues: PayjoinIndexedValue[];
  senderOutputs: number;
  recipientOutputs: number;
  fee: number;
  senderNetDebit: number;
  recipientNetGain: number;
}

export function calculatePayjoinDetails(
  inputValues: Array<number | null | undefined>,
  outputValues: Array<number | null | undefined>,
  ownership: PayjoinOwnership,
): PayjoinCalculation | null {
  if (inputValues.length !== ownership.inputs.length || outputValues.length !== ownership.outputs.length) {
    return null;
  }

  const values = [...inputValues, ...outputValues];
  if (values.some((value) => !Number.isSafeInteger(value) || value < 0)) {
    return null;
  }

  const inputs = inputValues as number[];
  const outputs = outputValues as number[];
  const indexedInputs = inputs.map((value, index) => ({ index, value }));
  const indexedOutputs = outputs.map((value, index) => ({ index, value }));
  const senderInputValues = indexedInputs.filter(({ index }) => ownership.inputs[index] === 'sender');
  const recipientInputValues = indexedInputs.filter(({ index }) => ownership.inputs[index] === 'recipient');
  const senderOutputValues = indexedOutputs.filter(({ index }) => ownership.outputs[index] === 'sender');
  const recipientOutputValues = indexedOutputs.filter(({ index }) => ownership.outputs[index] === 'recipient');
  const sumValues = (indexedValues: PayjoinIndexedValue[]): number => indexedValues.reduce((total, { value }) => total + value, 0);
  const senderInputs = sumValues(senderInputValues);
  const recipientInputs = sumValues(recipientInputValues);
  const senderOutputs = sumValues(senderOutputValues);
  const recipientOutputs = sumValues(recipientOutputValues);
  const totalInputs = senderInputs + recipientInputs;
  const totalOutputs = senderOutputs + recipientOutputs;
  const fee = totalInputs - totalOutputs;
  const senderNetDebit = senderInputs - senderOutputs;
  const recipientNetGain = recipientOutputs - recipientInputs;
  const calculatedValues = [
    senderInputs,
    recipientInputs,
    totalInputs,
    senderOutputs,
    recipientOutputs,
    totalOutputs,
    fee,
    senderNetDebit,
    recipientNetGain,
  ];

  if (
    calculatedValues.some((value) => !Number.isSafeInteger(value))
    || fee < 0
    || recipientNetGain <= 0
  ) {
    return null;
  }

  return {
    senderInputValues,
    recipientInputValues,
    senderInputs,
    recipientInputs,
    senderOutputValues,
    recipientOutputValues,
    senderOutputs,
    recipientOutputs,
    fee,
    senderNetDebit,
    recipientNetGain,
  };
}

const OWNERSHIP_CODES: Record<string, PayjoinOwner> = {
  s: 'sender',
  r: 'recipient',
};

/**
 * Read the `pj` fragment parameter: a version, one code per input, one code
 * per output, and optionally the sender's and the recipient's names, all
 * separated by colons. `1:ssr:rs` marks two sender inputs and one recipient
 * input; `1:ssr:rs:Alice:Bob` also names them. Names cannot contain a colon.
 */
export function parsePayjoinOwnership(
  value: string | null,
  inputCount: number,
  outputCount: number,
): PayjoinOwnership | null {
  if (!value) {
    return null;
  }

  const parts = value.split(':');
  if (parts.length < 3 || parts.length > 5 || parts[0] !== '1') {
    return null;
  }

  const inputCodes = Array.from(parts[1]);
  const outputCodes = Array.from(parts[2]);
  if (inputCodes.length !== inputCount || outputCodes.length !== outputCount) {
    return null;
  }
  if (!inputCodes.includes('s') || !inputCodes.includes('r')) {
    return null;
  }
  if ([...inputCodes, ...outputCodes].some((code) => !OWNERSHIP_CODES[code])) {
    return null;
  }

  return {
    inputs: inputCodes.map((code) => OWNERSHIP_CODES[code]),
    outputs: outputCodes.map((code) => OWNERSHIP_CODES[code]),
    labels: {
      sender: parseLabel(parts[3]),
      recipient: parseLabel(parts[4]),
    },
  };
}
