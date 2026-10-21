import { ChangeDetectionStrategy, Component, Input, OnChanges } from '@angular/core';
import { CisaInputCost, CisaSavings } from '@app/shared/cisa.utils';
import { PayjoinOwner, PayjoinOwnership, payjoinOwnerLabel } from '@app/shared/payjoin-ownership';

/**
 * What BIP 460 signature aggregation saved a transaction, against the same
 * transaction with every input signed on its own, and which inputs carry
 * no signature.
 */
@Component({
  selector: 'app-cisa-summary',
  templateUrl: './cisa-summary.component.html',
  styleUrls: ['./cisa-summary.component.scss'],
  standalone: false,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class CisaSummaryComponent implements OnChanges {
  @Input() savings: CisaSavings;
  /** who owns which input, from a payjoin ownership fragment */
  @Input() ownership: PayjoinOwnership | null = null;

  /** bytes that fill a slot: the longest element, plain or aggregated */
  scale = 65;

  ngOnChanges(): void {
    if (this.savings) {
      this.scale = Math.max(...this.savings.inputs.map((input) => Math.max(input.bytes, input.plainBytes)));
    }
  }

  width(bytes: number): number {
    return Math.max(4, (bytes / this.scale) * 100);
  }

  saved(input: CisaInputCost): number {
    return input.plainBytes - input.bytes;
  }

  owner(input: CisaInputCost): PayjoinOwner | null {
    return this.ownership?.inputs[input.index] ?? null;
  }

  ownerLabel(owner: PayjoinOwner): string {
    return payjoinOwnerLabel(this.ownership, owner);
  }
}
