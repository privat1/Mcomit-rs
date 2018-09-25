use common_types::secret::Secret;
use event_store::Event;
use ganp::ledger::Ledger;
use std::marker::PhantomData;
use swaps::common::TradeId;

#[derive(Clone, Debug)]
pub struct SentSwapRequest<SL: Ledger, TL: Ledger, SA, TA> {
    pub source_ledger: SL,
    pub target_ledger: TL,
    pub target_asset: TA,
    pub source_asset: SA,
    pub secret: Secret,
    pub target_ledger_success_identity: TL::Identity,
    pub source_ledger_success_identity: SL::Identity,
    pub source_ledger_lock_duration: SL::LockDuration,
}

impl<
        SL: Ledger,
        TL: Ledger,
        SA: Clone + Send + Sync + 'static,
        TA: Clone + Send + Sync + 'static,
    > Event for SentSwapRequest<SL, TL, SA, TA>
{
    type Prev = ();
}

#[derive(Clone, Debug)]
pub struct SwapRequestAccepted<SL: Ledger, TL: Ledger, SA, TA> {
    pub target_ledger_refund_address: TL::Address,
    pub source_ledger_success_address: SL::Address,
    pub target_ledger_lock_duration: TL::LockDuration,
    phantom: PhantomData<(SA, TA)>,
}

impl<SL: Ledger, TL: Ledger, SA, TA> SwapRequestAccepted<SL, TL, SA, TA> {
    pub fn new(
        target_ledger_refund_address: TL::Address,
        source_ledger_success_address: SL::Address,
        target_ledger_lock_duration: TL::LockDuration,
    ) -> Self {
        SwapRequestAccepted {
            target_ledger_refund_address,
            source_ledger_success_address,
            target_ledger_lock_duration,
            phantom: PhantomData,
        }
    }
}

impl<
        SL: Ledger,
        TL: Ledger,
        SA: Clone + Send + Sync + 'static,
        TA: Clone + Send + Sync + 'static,
    > Event for SwapRequestAccepted<SL, TL, SA, TA>
{
    type Prev = SentSwapRequest<SL, TL, SA, TA>;
}
#[derive(Clone)]
pub struct SwapRequestRejected<SL: Ledger, TL: Ledger, SA, TA> {
    phantom: PhantomData<(SL, TL, SA, TA)>,
}

impl<
        SL: Ledger,
        TL: Ledger,
        SA: Clone + Send + Sync + 'static,
        TA: Clone + Send + Sync + 'static,
    > Event for SwapRequestRejected<SL, TL, SA, TA>
{
    type Prev = SentSwapRequest<SL, TL, SA, TA>;
}

impl<SL: Ledger, TL: Ledger, SA, TA> SwapRequestRejected<SL, TL, SA, TA> {
    pub fn new(uid: TradeId, address: TL::Address) -> SwapRequestRejected<SL, TL, SA, TA> {
        SwapRequestRejected {
            phantom: PhantomData,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ContractDeployed<SL: Ledger, TL: Ledger, SA, TA> {
    pub uid: TradeId,
    pub address: TL::Address,
    phantom: PhantomData<(SL, SA, TA)>,
}

impl<SL: Ledger, TL: Ledger, SA, TA> ContractDeployed<SL, TL, SA, TA> {
    pub fn new(uid: TradeId, address: TL::Address) -> ContractDeployed<SL, TL, SA, TA> {
        ContractDeployed {
            uid,
            address,
            phantom: PhantomData,
        }
    }
}

impl<
        SL: Ledger,
        TL: Ledger,
        SA: Clone + Send + Sync + 'static,
        TA: Clone + Send + Sync + 'static,
    > Event for ContractDeployed<SL, TL, SA, TA>
{
    type Prev = ContractDeployed<SL, TL, SA, TA>;
}
