use crate::ethereum_wallet::{UnsignedTransaction, Wallet};
use comit_node::swap_protocols::rfc003::{
    ethereum::{Htlc, Seconds},
    SecretHash,
};
use ethereum_support::{
    web3::{transports::Http, Web3},
    Address, Bytes, CallRequest, EtherQuantity, Future, TransactionReceipt, TransactionRequest,
    H256, U256,
};
use std::{
    ops::DerefMut,
    sync::{Arc, Mutex},
};

#[allow(missing_debug_implementations)]
pub struct ParityClient {
    client: Arc<Web3<Http>>,
    wallet: Arc<dyn Wallet>,
    nonce: Mutex<U256>,
}

#[derive(Clone, Debug)]
pub struct EtherHtlcFundingParams {
    pub refund_address: Address,
    pub redeem_address: Address,
    pub time_lock: Seconds,
    pub amount: EtherQuantity,
    pub secret_hash: SecretHash,
}

lazy_static! {
    static ref PARITY_DEV_ACCOUNT: Address =
        "00a329c0648769a73afac7f9381e08fb43dbea72".parse().unwrap();
}

const ERC20_TOKEN_CONTRACT_CODE: &'static str = include_str!("erc20_token_contract.asm.hex");

const PARITY_DEV_PASSWORD: &str = "";

impl ParityClient {
    pub fn new<N: Into<U256>>(
        wallet: Arc<dyn Wallet>,
        client: Arc<Web3<Http>>,
        current_nonce: N,
    ) -> Self {
        ParityClient {
            wallet,
            nonce: Mutex::new(current_nonce.into()),
            client,
        }
    }

    pub fn give_eth_to(&self, to: Address, amount: EtherQuantity) {
        self.client
            .personal()
            .send_transaction(
                TransactionRequest {
                    from: PARITY_DEV_ACCOUNT.clone(),
                    to: Some(to),
                    gas: None,
                    gas_price: None,
                    value: Some(amount.wei()),
                    data: None,
                    nonce: None,
                    condition: None,
                },
                PARITY_DEV_PASSWORD,
            )
            .wait()
            .unwrap();
    }

    pub fn deploy_erc20_token_contract(&self) -> Address {
        let contract_tx_id = self
            .client
            .personal()
            .send_transaction(
                TransactionRequest {
                    from: PARITY_DEV_ACCOUNT.clone(),
                    to: None,
                    gas: Some(U256::from(4_000_000u64)),
                    gas_price: None,
                    value: None,
                    data: Some(Bytes(
                        hex::decode(ERC20_TOKEN_CONTRACT_CODE.trim()).unwrap(),
                    )),
                    nonce: None,
                    condition: None,
                },
                "",
            )
            .wait()
            .unwrap();

        let receipt = self
            .client
            .eth()
            .transaction_receipt(contract_tx_id)
            .wait()
            .unwrap()
            .unwrap();

        debug!("Deploying the contract consumed {} gas", receipt.gas_used);

        receipt.contract_address.unwrap()
    }

    pub fn get_contract_code(&self, address: Address) -> Bytes {
        self.client.eth().code(address, None).wait().unwrap()
    }

    pub fn get_contract_address(&self, txid: H256) -> Address {
        self.client
            .eth()
            .transaction_receipt(txid)
            .wait()
            .unwrap()
            .unwrap()
            .contract_address
            .unwrap()
    }

    pub fn mint_tokens(&self, contract: Address, amount: U256, to: Address) -> U256 {
        let function_identifier = "40c10f19";
        let address = format!("000000000000000000000000{}", hex::encode(to));
        let amount = format!("{:0>64}", format!("{:x}", amount));

        let payload = format!("{}{}{}", function_identifier, address, amount);

        self.send_data(contract, Some(Bytes(hex::decode(payload).unwrap())))
            .gas_used
    }

    pub fn token_balance_of(&self, contract: Address, address: Address) -> U256 {
        let function_identifier = "70a08231";
        let address_hex = format!("000000000000000000000000{}", hex::encode(address));

        let payload = format!("{}{}", function_identifier, address_hex);

        let result = self
            .client
            .eth()
            .call(
                CallRequest {
                    from: Some(address),
                    to: contract,
                    gas: None,
                    gas_price: None,
                    value: None,
                    data: Some(Bytes(hex::decode(payload).unwrap())),
                },
                None,
            )
            .wait()
            .unwrap();

        U256::from(result.0.as_slice())
    }

    pub fn eth_balance_of(&self, address: Address) -> U256 {
        self.client.eth().balance(address, None).wait().unwrap()
    }

    pub fn send_data(&self, to: Address, data: Option<Bytes>) -> TransactionReceipt {
        let result_tx = self
            .client
            .personal()
            .send_transaction(
                TransactionRequest {
                    from: PARITY_DEV_ACCOUNT.clone(),
                    to: Some(to),
                    gas: None,
                    gas_price: None,
                    value: None,
                    data,
                    nonce: None,
                    condition: None,
                },
                "",
            )
            .wait()
            .unwrap();

        let receipt = self
            .client
            .eth()
            .transaction_receipt(result_tx)
            .wait()
            .unwrap()
            .unwrap();

        debug!("Transaction Receipt: {:?}", receipt);

        receipt
    }

    pub fn deploy_htlc(&self, htlc: impl Htlc, value: U256) -> H256 {
        self.sign_and_send(|nonce, gas_price| UnsignedTransaction {
            nonce,
            gas_price,
            gas_limit: U256::from(500_000),
            to: None,
            value,
            data: Some(htlc.compile_to_hex().into()),
        })
    }

    pub fn sign_and_send<T: Fn(U256, U256) -> UnsignedTransaction>(
        &self,
        transaction_fn: T,
    ) -> H256 {
        let gas_price = U256::from(100);

        let tx_id = {
            let mut lock = self.nonce.lock().unwrap();

            let nonce = lock.deref_mut();

            let transaction = transaction_fn(*nonce, gas_price);

            // println!("{:?}", transaction);

            let signed_transaction = self.wallet.sign(&transaction);

            // println!("{:?}", Bytes::from(signed_transaction.clone()));

            // let failed_signed_transaction = Bytes(vec![
            //     249, 1, 161, 128, 100, 131, 7, 161, 32, 128, 128, 185, 1, 83, 97, 1, 68,
            // 97, 0, 15,     96, 0, 57, 97, 1, 68, 96, 0, 243, 54, 21, 97, 0,
            // 84, 87, 96, 32, 54, 20, 21, 97, 0,     96, 87, 96, 32, 96, 0, 96,
            // 0, 55, 96, 32, 96, 33, 96, 32, 96, 0, 96, 0, 96, 2, 96,
            //     72, 241, 127, 104, 214, 39, 151, 22, 67, 166, 249, 127, 39, 197, 137, 87,
            // 130, 111,     203, 168, 83, 236, 32, 119, 253, 16, 236, 107, 147,
            // 216, 230, 29, 235, 76, 236, 96,     33, 81, 20, 22, 97, 0, 102,
            // 87, 96, 0, 96, 0, 243, 91, 66, 99, 92, 88, 207, 96, 16,
            //     97, 0, 169, 87, 91, 96, 0, 96, 0, 243, 91, 127, 184, 202, 195, 0, 227,
            // 127, 3, 173,     51, 46, 88, 29, 234, 33, 178, 240, 184, 78, 170,
            // 173, 193, 132, 162, 149, 254, 247,     30, 129, 244, 74, 116, 19,
            // 96, 0, 96, 0, 161, 115, 213, 30, 206, 231, 65, 76, 68,
            //     69, 83, 79, 116, 32, 133, 56, 104, 55, 2, 203, 179, 228, 96, 32, 82, 97,
            // 0, 236,     86, 91, 127, 93, 38, 134, 41, 22, 57, 27, 244, 148,
            // 120, 178, 245, 16, 59, 7, 32,     168, 66, 180, 94, 241, 69, 162,
            // 104, 242, 205, 31, 178, 174, 213, 81, 120, 96, 0,     96, 0, 161,
            // 115, 192, 85, 214, 63, 232, 138, 77, 144, 25, 251, 231, 9, 192, 78, 90,
            //     228, 225, 3, 55, 16, 96, 32, 82, 97, 0, 236, 86, 91, 99, 169, 5, 156,
            // 187, 96, 0,     82, 127, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            // 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,     0, 0, 0, 0, 0, 1, 144,
            // 96, 64, 82, 96, 32, 96, 96, 96, 68, 96, 28, 96, 0, 115, 180,
            //     199, 157, 171, 143, 37, 156, 122, 238, 110, 91, 42, 167, 41, 130, 24,
            // 100, 34, 126,     132, 98, 1, 134, 160, 90, 3, 241, 80, 96, 32,
            // 81, 255, 37, 160, 0, 3, 136, 33, 184,     54, 40, 126, 123, 148,
            // 193, 129, 54, 139, 235, 77, 134, 30, 135, 46, 136, 142, 81,
            //     195, 198, 96, 7, 196, 210, 53, 210, 150, 160, 89, 155, 77, 142, 37, 154,
            // 194, 248,     170, 38, 117, 174, 152, 217, 111, 207, 3, 52, 8,
            // 115, 52, 230, 17, 59, 232, 141,     52, 96, 166, 233, 252, 19,
            // ]);

            let tx_id = self
                .client
                .eth()
                .send_raw_transaction(signed_transaction.into())
                .wait()
                .unwrap();

            // If we get this far, everything worked.
            // Update the nonce and release the lock.
            self.increment_nonce(nonce);

            tx_id
        };

        tx_id
    }

    fn increment_nonce(&self, nonce: &mut U256) {
        let next_nonce = *nonce + U256::from(1);
        debug!("Nonce was incremented from {} to {}", nonce, next_nonce);
        *nonce = next_nonce;
    }
}
