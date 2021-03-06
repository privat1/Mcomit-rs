import * as bitcoin from "../../../lib/bitcoin";
import * as ethereum from "../../../lib/ethereum";
import { Actor } from "../../../lib/actor";
import { ActionKind, SwapRequest } from "../../../lib/comit";
import { toBN, toWei } from "web3-utils";
import { HarnessGlobal } from "../../../lib/util";
import { ActionTrigger, createTests } from "../../test_creator";
import "chai/register-should";
import "../../../lib/setupChai";

declare var global: HarnessGlobal;

(async function() {
    const bobInitialEth = "11";
    const aliceInitialEth = "0.1";

    const alice = new Actor("alice", global.config, global.project_root, {
        ethConfig: global.ledgers_config.ethereum,
        btcConfig: global.ledgers_config.bitcoin,
    });
    const bob = new Actor("bob", global.config, global.project_root, {
        ethConfig: global.ledgers_config.ethereum,
        btcConfig: global.ledgers_config.bitcoin,
    });

    const aliceFinalAddress = "0x03a329c0248369a73afac7f9381e02fb43d2ea72";
    const aliceRefundAddress =
        "bcrt1qs2aderg3whgu0m8uadn6dwxjf7j3wx97kk2qqtrum89pmfcxknhsf89pj0";
    const bobComitNodeListen = await bob.peerId();

    const alphaAssetQuantity = 100000000;
    const betaAssetQuantity = toBN(toWei("10", "ether"));
    const alphaMaxFee = 5000; // Max 5000 satoshis fee

    const alphaExpiry: number = Math.round(Date.now() / 1000) + 13;
    const betaExpiry: number = Math.round(Date.now() / 1000) + 8;

    const initialUrl = "/swaps/rfc003";
    const listUrl = "/swaps";

    await bitcoin.ensureFunding();
    await bob.wallet.eth().fund(bobInitialEth);
    await alice.wallet.eth().fund(aliceInitialEth);
    await alice.wallet.btc().fund(10);
    await bitcoin.generate();

    let swapRequest: SwapRequest = {
        alpha_ledger: {
            name: "bitcoin",
            network: "regtest",
        },
        beta_ledger: {
            name: "ethereum",
            network: "regtest",
        },
        alpha_asset: {
            name: "bitcoin",
            quantity: alphaAssetQuantity.toString(),
        },
        beta_asset: {
            name: "ether",
            quantity: betaAssetQuantity.toString(),
        },
        beta_ledger_redeem_identity: aliceFinalAddress,
        alpha_expiry: alphaExpiry,
        beta_expiry: betaExpiry,
        peer: bobComitNodeListen,
    };

    const actions: ActionTrigger[] = [
        {
            actor: bob,
            action: ActionKind.Accept,
            requestBody: {
                beta_ledger_refund_identity: bob.wallet.eth().address(),
            },
            state: state => state.communication.status === "ACCEPTED",
        },
        {
            actor: alice,
            action: ActionKind.Fund,
            state: state => state.alpha_ledger.status === "Funded",
        },
        {
            actor: bob,
            action: ActionKind.Fund,
            state: state =>
                state.alpha_ledger.status === "Funded" &&
                state.beta_ledger.status === "Funded",
            test: {
                description:
                    "[bob] Should have less beta asset after the funding",
                callback: async () => {
                    const bobWeiBalanceAfter = await ethereum.ethBalance(
                        bob.wallet.eth().address()
                    );
                    const bobWeiBalanceInit = toWei(toBN(bobInitialEth));

                    bobWeiBalanceAfter
                        .lt(bobWeiBalanceInit)
                        .should.be.equal(true);
                },
                timeout: 10000,
            },
        },
        {
            actor: bob,
            action: ActionKind.Refund,
            state: state => state.beta_ledger.status === "Refunded",
            test: {
                description:
                    "Should have received the beta asset after the refund",
                callback: async () => {
                    const bobWeiBalanceAfter = await ethereum.ethBalance(
                        bob.wallet.eth().address()
                    );
                    const bobWeiBalanceInit = toWei(toBN(bobInitialEth));

                    bobWeiBalanceAfter
                        .eq(bobWeiBalanceInit)
                        .should.be.equal(true);
                },
            },
        },
        {
            actor: alice,
            action: ActionKind.Refund,
            uriQuery: { address: aliceRefundAddress, fee_per_byte: 20 },
        },
        {
            actor: alice,
            state: state =>
                state.alpha_ledger.status === "Refunded" &&
                state.beta_ledger.status === "Refunded",
            test: {
                description:
                    "Should have received the alpha asset after the refund",
                callback: async body => {
                    let refundTxId =
                        body.properties.state.alpha_ledger.refund_tx;

                    let satoshiReceived = await bitcoin.getFirstUtxoValueTransferredTo(
                        refundTxId,
                        aliceRefundAddress
                    );
                    const satoshiExpected = alphaAssetQuantity - alphaMaxFee;

                    satoshiReceived.should.be.at.least(satoshiExpected);
                },
            },
        },
    ];

    describe("RFC003: Bitcoin for Ether - Both refunded", async () => {
        createTests(alice, bob, actions, initialUrl, listUrl, swapRequest);
    });
    run();
})();
