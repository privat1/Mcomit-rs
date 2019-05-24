use crate::swap_protocols::{
    actions::bitcoin::{SendToAddress, SpendOutput},
    ledger::Bitcoin,
    rfc003::{
        actions::{FundAction, RedeemAction, RefundAction},
        bitcoin::Htlc,
        secret_source::SecretSource,
        state_machine::HtlcParams,
        Secret,
    },
};
use bitcoin_support::{BitcoinQuantity, OutPoint};
use bitcoin_witness::PrimedInput;

impl FundAction<Bitcoin, BitcoinQuantity> for (Bitcoin, BitcoinQuantity) {
    type FundActionOutput = SendToAddress;

    fn fund_action(htlc_params: HtlcParams<Bitcoin, BitcoinQuantity>) -> Self::FundActionOutput {
        let to = htlc_params.compute_address();

        SendToAddress {
            to,
            amount: htlc_params.asset,
            network: htlc_params.ledger.network,
        }
    }
}

impl RefundAction<Bitcoin, BitcoinQuantity> for (Bitcoin, BitcoinQuantity) {
    type RefundActionOutput = SpendOutput;

    fn refund_action(
        htlc_params: HtlcParams<Bitcoin, BitcoinQuantity>,
        htlc_location: OutPoint,
        secret_source: &dyn SecretSource,
    ) -> Self::RefundActionOutput {
        let htlc = Htlc::from(htlc_params.clone());

        SpendOutput {
            output: PrimedInput::new(
                htlc_location,
                htlc_params.asset,
                htlc.unlock_after_timeout(secret_source.secp256k1_refund()),
            ),
            network: htlc_params.ledger.network,
        }
    }
}

impl RedeemAction<Bitcoin, BitcoinQuantity> for (Bitcoin, BitcoinQuantity) {
    type RedeemActionOutput = SpendOutput;

    fn redeem_action(
        htlc_params: HtlcParams<Bitcoin, BitcoinQuantity>,
        htlc_location: OutPoint,
        secret_source: &dyn SecretSource,
        secret: Secret,
    ) -> Self::RedeemActionOutput {
        let htlc = Htlc::from(htlc_params.clone());

        SpendOutput {
            output: PrimedInput::new(
                htlc_location,
                htlc_params.asset,
                htlc.unlock_with_secret(secret_source.secp256k1_redeem(), &secret),
            ),
            network: htlc_params.ledger.network,
        }
    }
}
