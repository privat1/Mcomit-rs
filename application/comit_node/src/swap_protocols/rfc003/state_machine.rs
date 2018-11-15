use futures::{future::Either, Async, Future};
use state_machine_future::{RentToOwn, StateMachineFuture};
use std::sync::Arc;
use swap_protocols::{
    asset::Asset,
    rfc003::{
        self, events, ledger::Ledger, messages::Request, AcceptResponseBody, ExtractSecret,
        IntoSecretHash, SaveState, Secret, SwapOutcome,
    },
};

#[derive(Debug, Clone, PartialEq)]
pub struct OngoingSwap<SL: Ledger, TL: Ledger, SA: Asset, TA: Asset, S: Clone> {
    pub source_ledger: SL,
    pub target_ledger: TL,
    pub source_asset: SA,
    pub target_asset: TA,
    pub source_ledger_success_identity: SL::Identity,
    pub source_ledger_refund_identity: SL::HtlcIdentity,
    pub target_ledger_success_identity: TL::HtlcIdentity,
    pub target_ledger_refund_identity: TL::Identity,
    pub source_ledger_lock_duration: SL::LockDuration,
    pub target_ledger_lock_duration: TL::LockDuration,
    pub secret: S,
}

impl<SL: Ledger, TL: Ledger, SA: Asset, TA: Asset, S: IntoSecretHash> OngoingSwap<SL, TL, SA, TA, S>
where
    TL::Transaction: ExtractSecret,
{
    pub fn new(start: Start<SL, TL, SA, TA, S>, response: AcceptResponseBody<SL, TL>) -> Self {
        OngoingSwap {
            source_ledger: start.source_ledger,
            target_ledger: start.target_ledger,
            source_asset: start.source_asset,
            target_asset: start.target_asset,
            source_ledger_success_identity: response.source_ledger_success_identity,
            source_ledger_refund_identity: start.source_ledger_refund_identity,
            target_ledger_success_identity: start.target_ledger_success_identity,
            target_ledger_refund_identity: response.target_ledger_refund_identity,
            source_ledger_lock_duration: start.source_ledger_lock_duration,
            target_ledger_lock_duration: response.target_ledger_lock_duration,
            secret: start.secret,
        }
    }
}

#[allow(missing_debug_implementations)]
pub struct Context<SL: Ledger, TL: Ledger, SA: Asset, TA: Asset, S: IntoSecretHash> {
    pub events: Box<events::Events<SL, TL, SA, TA, S>>,
    pub state_repo: Arc<SaveState<SL, TL, SA, TA, S>>,
}

#[derive(StateMachineFuture)]
#[state_machine_future(context = "Context", derive(Clone, Debug, PartialEq))]
#[allow(missing_debug_implementations)]
pub enum Swap<SL: Ledger, TL: Ledger, SA: Asset, TA: Asset, S: IntoSecretHash>
where
    TL::Transaction: ExtractSecret,
{
    #[state_machine_future(start, transitions(Accepted, Final))]
    Start {
        source_ledger_refund_identity: SL::HtlcIdentity,
        target_ledger_success_identity: TL::HtlcIdentity,
        source_ledger: SL,
        target_ledger: TL,
        source_asset: SA,
        target_asset: TA,
        source_ledger_lock_duration: SL::LockDuration,
        secret: S,
    },

    #[state_machine_future(transitions(SourceFunded))]
    Accepted {
        swap: OngoingSwap<SL, TL, SA, TA, S>,
    },

    #[state_machine_future(transitions(BothFunded, Final))]
    SourceFunded {
        swap: OngoingSwap<SL, TL, SA, TA, S>,
        source_htlc_location: SL::HtlcLocation,
    },

    #[state_machine_future(transitions(
        SourceFundedTargetRedeemed,
        SourceFundedTargetRefunded,
        SourceRefundedTargetFunded,
        SourceRedeemedTargetFunded,
        Error
    ))]
    BothFunded {
        swap: OngoingSwap<SL, TL, SA, TA, S>,
        target_htlc_location: TL::HtlcLocation,
        source_htlc_location: SL::HtlcLocation,
    },

    #[state_machine_future(transitions(Final))]
    SourceFundedTargetRefunded {
        swap: OngoingSwap<SL, TL, SA, TA, S>,
        source_htlc_location: SL::HtlcLocation,
    },

    #[state_machine_future(transitions(Final))]
    SourceRefundedTargetFunded {
        swap: OngoingSwap<SL, TL, SA, TA, S>,
        target_htlc_location: TL::HtlcLocation,
    },

    #[state_machine_future(transitions(Final))]
    SourceRedeemedTargetFunded {
        swap: OngoingSwap<SL, TL, SA, TA, S>,
        target_htlc_location: TL::HtlcLocation,
    },

    #[state_machine_future(transitions(Final))]
    SourceFundedTargetRedeemed {
        swap: OngoingSwap<SL, TL, SA, TA, S>,
        target_redeemed_tx: TL::Transaction,
        source_htlc_location: SL::HtlcLocation,
        secret: Secret,
    },

    #[state_machine_future(ready)]
    Final(SwapOutcome),

    #[state_machine_future(error)]
    Error(rfc003::Error),
}

impl<SL: Ledger, TL: Ledger, SA: Asset, TA: Asset, S: IntoSecretHash> PollSwap<SL, TL, SA, TA, S>
    for Swap<SL, TL, SA, TA, S>
where
    TL::Transaction: ExtractSecret,
{
    fn poll_start<'s, 'c>(
        state: &'s mut RentToOwn<'s, Start<SL, TL, SA, TA, S>>,
        context: &'c mut RentToOwn<'c, Context<SL, TL, SA, TA, S>>,
    ) -> Result<Async<AfterStart<SL, TL, SA, TA, S>>, rfc003::Error> {
        let request = Request {
            source_asset: state.source_asset.clone(),
            target_asset: state.target_asset.clone(),
            source_ledger: state.source_ledger.clone(),
            target_ledger: state.target_ledger.clone(),
            source_ledger_refund_identity: state.source_ledger_refund_identity.clone().into(),
            target_ledger_success_identity: state.target_ledger_success_identity.clone().into(),
            source_ledger_lock_duration: state.source_ledger_lock_duration.clone(),
            secret_hash: state.secret.clone().into(),
        };

        let response = try_ready!(context.events.request_responded(&request).poll());

        let state = state.take();

        match response {
            Ok(swap_accepted) => transition_save!(
                context.state_repo,
                Accepted {
                    swap: OngoingSwap::new(state, swap_accepted),
                }
            ),
            Err(_) => transition_save!(context.state_repo, Final(SwapOutcome::Rejected)),
        }
    }

    fn poll_accepted<'s, 'c>(
        state: &'s mut RentToOwn<'s, Accepted<SL, TL, SA, TA, S>>,
        context: &'c mut RentToOwn<'c, Context<SL, TL, SA, TA, S>>,
    ) -> Result<Async<AfterAccepted<SL, TL, SA, TA, S>>, rfc003::Error> {
        let source_htlc_location =
            try_ready!(context.events.source_htlc_funded(&state.swap).poll());

        let state = state.take();

        transition_save!(
            context.state_repo,
            SourceFunded {
                swap: state.swap,
                source_htlc_location,
            }
        )
    }

    fn poll_source_funded<'s, 'c>(
        state: &'s mut RentToOwn<'s, SourceFunded<SL, TL, SA, TA, S>>,
        context: &'c mut RentToOwn<'c, Context<SL, TL, SA, TA, S>>,
    ) -> Result<Async<AfterSourceFunded<SL, TL, SA, TA, S>>, rfc003::Error> {
        match try_ready!(context
            .events
            .source_htlc_refunded_target_htlc_funded(&state.swap, &state.source_htlc_location)
            .poll())
        {
            Either::A(_source_refunded_txid) => {
                transition_save!(context.state_repo, Final(SwapOutcome::SourceRefunded))
            }
            Either::B(target_htlc_location) => {
                let state = state.take();
                transition_save!(
                    context.state_repo,
                    BothFunded {
                        swap: state.swap,
                        source_htlc_location: state.source_htlc_location,
                        target_htlc_location,
                    }
                )
            }
        }
    }

    fn poll_both_funded<'s, 'c>(
        state: &'s mut RentToOwn<'s, BothFunded<SL, TL, SA, TA, S>>,
        context: &'c mut RentToOwn<'c, Context<SL, TL, SA, TA, S>>,
    ) -> Result<Async<AfterBothFunded<SL, TL, SA, TA, S>>, rfc003::Error> {
        if let Async::Ready(redeemed_or_refunded) = context
            .events
            .target_htlc_redeemed_or_refunded(&state.swap, &state.target_htlc_location)
            .poll()?
        {
            let state = state.take();
            let secret_hash = state.swap.secret.clone().into();
            match redeemed_or_refunded {
                Either::A(target_redeemed_tx) => {
                    match target_redeemed_tx.extract_secret(&secret_hash) {
                        Some(secret) => transition_save!(
                            context.state_repo,
                            SourceFundedTargetRedeemed {
                                swap: state.swap,
                                target_redeemed_tx,
                                source_htlc_location: state.source_htlc_location,
                                secret,
                            }
                        ),
                        None => transition_save!(
                        context.state_repo,
                        Error (rfc003::Error::Internal(format!("Somehow reached transition with an invalid secret, transaction: {:?}", target_redeemed_tx).to_string()))
                    ),
                    }
                }
                Either::B(_target_refunded_txid) => transition_save!(
                    context.state_repo,
                    SourceFundedTargetRefunded {
                        swap: state.swap,
                        source_htlc_location: state.source_htlc_location,
                    }
                ),
            }
        }

        match try_ready!(context
            .events
            .source_htlc_redeemed_or_refunded(&state.swap, &state.source_htlc_location)
            .poll())
        {
            Either::A(_source_redeemed_tx) => {
                let state = state.take();
                transition_save!(
                    context.state_repo,
                    SourceRedeemedTargetFunded {
                        swap: state.swap,
                        target_htlc_location: state.target_htlc_location,
                    }
                )
            }
            Either::B(_source_refunded_txid) => {
                let state = state.take();
                transition_save!(
                    context.state_repo,
                    SourceRefundedTargetFunded {
                        swap: state.swap,
                        target_htlc_location: state.target_htlc_location,
                    }
                )
            }
        }
    }

    fn poll_source_funded_target_refunded<'s, 'c>(
        state: &'s mut RentToOwn<'s, SourceFundedTargetRefunded<SL, TL, SA, TA, S>>,
        context: &'c mut RentToOwn<'c, Context<SL, TL, SA, TA, S>>,
    ) -> Result<Async<AfterSourceFundedTargetRefunded>, rfc003::Error> {
        match try_ready!(context
            .events
            .source_htlc_redeemed_or_refunded(&state.swap, &state.source_htlc_location)
            .poll())
        {
            Either::A(_source_redeemed_txid) => transition_save!(
                context.state_repo,
                Final(SwapOutcome::SourceRedeemedTargetRefunded)
            ),
            Either::B(_source_refunded_txid) => {
                transition_save!(context.state_repo, Final(SwapOutcome::BothRefunded))
            }
        }
    }

    fn poll_source_refunded_target_funded<'s, 'c>(
        state: &'s mut RentToOwn<'s, SourceRefundedTargetFunded<SL, TL, SA, TA, S>>,
        context: &'c mut RentToOwn<'c, Context<SL, TL, SA, TA, S>>,
    ) -> Result<Async<AfterSourceRefundedTargetFunded>, rfc003::Error> {
        match try_ready!(context
            .events
            .target_htlc_redeemed_or_refunded(&state.swap, &state.target_htlc_location)
            .poll())
        {
            Either::A(_target_redeemed_txid) => transition_save!(
                context.state_repo,
                Final(SwapOutcome::SourceRefundedTargetRedeemed)
            ),
            Either::B(_target_refunded_txid) => {
                transition_save!(context.state_repo, Final(SwapOutcome::BothRefunded))
            }
        }
    }

    fn poll_source_redeemed_target_funded<'s, 'c>(
        state: &'s mut RentToOwn<'s, SourceRedeemedTargetFunded<SL, TL, SA, TA, S>>,
        context: &'c mut RentToOwn<'c, Context<SL, TL, SA, TA, S>>,
    ) -> Result<Async<AfterSourceRedeemedTargetFunded>, rfc003::Error> {
        match try_ready!(context
            .events
            .target_htlc_redeemed_or_refunded(&state.swap, &state.target_htlc_location)
            .poll())
        {
            Either::A(_target_redeemed_txid) => {
                transition_save!(context.state_repo, Final(SwapOutcome::BothRedeemed))
            }
            Either::B(_target_refunded_txid) => transition_save!(
                context.state_repo,
                Final(SwapOutcome::SourceRedeemedTargetRefunded)
            ),
        }
    }

    fn poll_source_funded_target_redeemed<'s, 'c>(
        state: &'s mut RentToOwn<'s, SourceFundedTargetRedeemed<SL, TL, SA, TA, S>>,
        context: &'c mut RentToOwn<'c, Context<SL, TL, SA, TA, S>>,
    ) -> Result<Async<AfterSourceFundedTargetRedeemed>, rfc003::Error> {
        match try_ready!(context
            .events
            .source_htlc_redeemed_or_refunded(&state.swap, &state.source_htlc_location)
            .poll())
        {
            Either::A(_target_redeemed_txid) => {
                transition_save!(context.state_repo, Final(SwapOutcome::BothRedeemed))
            }
            Either::B(_target_refunded_txid) => transition_save!(
                context.state_repo,
                Final(SwapOutcome::SourceRefundedTargetRedeemed)
            ),
        }
    }
}
