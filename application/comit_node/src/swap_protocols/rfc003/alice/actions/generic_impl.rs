use crate::swap_protocols::{
    actions::Actions,
    asset::Asset,
    rfc003::{
        actions::{Accept, ActionKind, Decline, FundAction, RedeemAction, RefundAction},
        alice::{self, SwapCommunication},
        state_machine::HtlcParams,
        Ledger, LedgerState,
    },
};
use std::convert::Infallible;

impl<AL, BL, AA, BA> Actions for alice::State<AL, BL, AA, BA>
where
    AL: Ledger,
    BL: Ledger,
    AA: Asset,
    BA: Asset,
    (AL, AA): FundAction<AL, AA>,
    (AL, AA): RefundAction<AL, AA>,
    (BL, BA): RedeemAction<BL, BA>,
{
    #[allow(clippy::type_complexity)]
    type ActionKind = ActionKind<
        Accept<AL, BL>,
        Decline<BL, BL>,
        Infallible,
        <(AL, AA) as FundAction<AL, AA>>::FundActionOutput,
        <(BL, BA) as RedeemAction<BL, BA>>::RedeemActionOutput,
        <(AL, AA) as RefundAction<AL, AA>>::RefundActionOutput,
    >;

    fn actions(&self) -> Vec<Self::ActionKind> {
        let (request, response) = match self.swap_communication {
            SwapCommunication::Accepted {
                ref request,
                ref response,
            } => (request, response),
            _ => return vec![],
        };
        let alpha_state = &self.alpha_ledger_state;
        let beta_state = &self.beta_ledger_state;

        use self::LedgerState::*;
        let mut actions = match alpha_state {
            NotDeployed => vec![ActionKind::Fund(<(AL, AA)>::fund_action(
                HtlcParams::new_alpha_params(request, response),
            ))],
            Funded { htlc_location, .. } => vec![ActionKind::Refund(<(AL, AA)>::refund_action(
                HtlcParams::new_alpha_params(request, response),
                htlc_location.clone(),
                &*self.secret_source,
            ))],
            _ => vec![],
        };

        if let Funded { htlc_location, .. } = beta_state {
            actions.push(ActionKind::Redeem(<(BL, BA)>::redeem_action(
                HtlcParams::new_beta_params(request, response),
                htlc_location.clone(),
                &*self.secret_source,
                self.secret_source.secret(),
            )));
        }
        actions
    }
}
