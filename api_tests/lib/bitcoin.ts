import {
    Transaction,
    ECPair,
    Out,
    payments,
    networks,
    TransactionBuilder,
    address,
} from "bitcoinjs-lib";

const BitcoinRpcClient = require("bitcoin-core");
const sb = require("satoshi-bitcoin");
const util = require("./util.js");

// TODO: Remove regtest
// Once this is merged: https://github.com/DefinitelyTyped/DefinitelyTyped/pull/33571

const networksAny: any = networks;
const regtest: any = networksAny.regtest;

interface BitcoinConfig {
    // snake_case because it comes from TOML file
    rpc_username: string;
    rpc_password: string;
    rpc_host: string;
    rpc_port: number;
}

interface BitcoinRpcClient {
    // TODO: Create Interface for Promise returned by RPC calls
    // We should avoid to use `any` and instead create the interface
    // of what is returned by the RPC calls
    generate(num: number): Promise<any>;

    getBlockCount(): Promise<number>;

    getRawTransaction(
        txId: string,
        verbose?: boolean,
        blockHash?: string
    ): Promise<any>;

    sendToAddress(address: string, amount: number | string): Promise<any>;

    sendRawTransaction(hexString: string): Promise<any>;
}

interface Utxo {
    // TODO: declare transactionId type
    // Best to have specific transactionId type than using generic strings
    txId: string;
    value: number;
    vout: number;
}

let _bitcoinRpcClient: BitcoinRpcClient;
let _bitcoinConfig: BitcoinConfig;

function createBitcoinRpcClient(btcConfig: BitcoinConfig) {
    if (!btcConfig && !_bitcoinConfig) {
        throw new Error("bitcoin configuration is needed");
    }

    if (!_bitcoinRpcClient || btcConfig !== _bitcoinConfig) {
        _bitcoinRpcClient = new BitcoinRpcClient({
            network: "regtest",
            port: btcConfig.rpc_port,
            host: btcConfig.rpc_host,
            username: btcConfig.rpc_username,
            password: btcConfig.rpc_password,
        });
        _bitcoinConfig = btcConfig;
    }
    return _bitcoinRpcClient;
}

module.exports.createClient = (btcConfig: BitcoinConfig) => {
    return createBitcoinRpcClient(btcConfig);
};

module.exports.generate = async function(num: number = 1) {
    return createBitcoinRpcClient(_bitcoinConfig).generate(num);
};

module.exports.ensureSegwit = async function() {
    const blockHeight = await createBitcoinRpcClient(
        _bitcoinConfig
    ).getBlockCount();
    if (blockHeight < 432) {
        await createBitcoinRpcClient(_bitcoinConfig).generate(432);
    }
};

async function getFirstUtxoValueTransferredTo(txId: string, address: string) {
    let satoshi = 0;
    let tx = await _bitcoinRpcClient.getRawTransaction(txId, true);
    let vout = tx.vout[0];

    if (
        vout.scriptPubKey.addresses.length === 1 &&
        vout.scriptPubKey.addresses[0] === address
    ) {
        satoshi = sb.toSatoshi(vout.value);
    }

    return satoshi;
}

module.exports.get_first_utxo_value_transferred_to = getFirstUtxoValueTransferredTo;

export class BitcoinWallet {
    keypair: ECPair;
    bitcoinUtxos: Utxo[];
    _identity: {
        address: string;
        hash: Buffer;
        output: Buffer;
        pubkey: Buffer;
        signature: Buffer;
        input: Buffer;
        witness: Buffer[];
    };

    constructor() {
        this.keypair = ECPair.makeRandom({ rng: util.test_rng });
        // TODO: Use wallet instead of array to track Bitcoin UTXOs
        this.bitcoinUtxos = [];
        this._identity = payments.p2wpkh({
            pubkey: this.keypair.publicKey,
            network: regtest,
        });
    }

    identity() {
        return this._identity;
    }

    async fund(btcValue: number) {
        let txId = await _bitcoinRpcClient.sendToAddress(
            this.identity().address,
            btcValue
        );
        let raw_transaction = await _bitcoinRpcClient.getRawTransaction(txId);
        let transaction = Transaction.fromHex(raw_transaction);
        let entries: Out[] = transaction.outs;
        this.bitcoinUtxos.push(
            ...entries
                .filter(entry => entry.script.equals(this.identity().output))
                .map(entry => {
                    return {
                        txId: txId,
                        vout: entries.indexOf(entry),
                        value: entry.value,
                    };
                })
        );
    }

    async sendToAddress(to: string, value: number) {
        const txb = new TransactionBuilder();
        const utxo = this.bitcoinUtxos.shift();
        const input_amount = utxo.value;
        const key_pair = this.keypair;
        const fee = 2500;
        const change = input_amount - value - fee;
        txb.addInput(utxo.txId, utxo.vout, null, this.identity().output);
        txb.addOutput(this.identity().output, change);
        txb.addOutput(address.toOutputScript(to, regtest), value);
        txb.sign(0, key_pair, null, null, input_amount);

        return _bitcoinRpcClient.sendRawTransaction(txb.build().toHex());
    }
}

export function createBitcoinWallet() {
    return new BitcoinWallet();
}