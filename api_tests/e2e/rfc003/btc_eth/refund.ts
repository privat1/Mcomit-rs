import * as bitcoin from "../../../lib/bitcoin";
import { Actor } from "../../../lib/actor";
import { ActionKind, SwapRequest } from "../../../lib/comit";
import { toBN, toWei } from "web3-utils";
import { HarnessGlobal } from "../../../lib/util";
import { Step, createTests } from "../../test_creator";
import "chai/register-should";
import "../../../lib/setupChai";

declare var global: HarnessGlobal;

(async function() {
    const alice = new Actor("alice", global.config, global.project_root, {
        ethereumNodeConfig: global.ledgers_config.ethereum,
        bitcoinNodeConfig: global.ledgers_config.bitcoin,
        addressForIncomingBitcoinPayments:
            "bcrt1qs2aderg3whgu0m8uadn6dwxjf7j3wx97kk2qqtrum89pmfcxknhsf89pj0",
    });
    const bob = new Actor("bob", global.config, global.project_root, {
        ethereumNodeConfig: global.ledgers_config.ethereum,
        bitcoinNodeConfig: global.ledgers_config.bitcoin,
    });

    const alphaAssetQuantity = 100000000;
    const betaAssetQuantity = toBN(toWei("10", "ether"));
    const maxFeeInSatoshi = 5000;

    const alphaExpiry = Math.round(Date.now() / 1000) + 13;
    const betaExpiry = Math.round(Date.now() / 1000) + 8;

    await bitcoin.ensureFunding();
    await bob.wallet.eth().fund("11");
    await alice.wallet.eth().fund("0.1");
    await alice.wallet.btc().fund(10);
    await bitcoin.generate();

    const bobInitialWei = await bob.wallet.eth().ethBalance();

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
        beta_ledger_redeem_identity: alice.wallet.eth().address(),
        alpha_expiry: alphaExpiry,
        beta_expiry: betaExpiry,
        peer: await bob.peerId(),
    };

    const steps: Step[] = [
        {
            actor: bob,
            action: ActionKind.Accept,
            waitUntil: state => state.communication.status === "ACCEPTED",
        },
        {
            actor: alice,
            action: ActionKind.Fund,
            waitUntil: state => state.alpha_ledger.status === "Funded",
        },
        {
            actor: bob,
            action: ActionKind.Fund,
            waitUntil: state =>
                state.alpha_ledger.status === "Funded" &&
                state.beta_ledger.status === "Funded",
            test: {
                description: "Should have less beta asset after the funding",
                callback: async () => {
                    const bobWeiBalanceAfter = await bob.wallet
                        .eth()
                        .ethBalance();

                    bobWeiBalanceAfter.lt(bobInitialWei).should.be.equal(true);
                },
            },
        },
        {
            actor: bob,
            action: ActionKind.Refund,
            waitUntil: state => state.beta_ledger.status === "Refunded",
            test: {
                description:
                    "Should have received the beta asset after the refund",
                callback: async () => {
                    const bobWeiBalanceAfter = await bob.wallet
                        .eth()
                        .ethBalance();

                    bobWeiBalanceAfter.eq(bobInitialWei).should.be.equal(true);
                },
            },
        },
        {
            actor: alice,
            action: ActionKind.Refund,
        },
        {
            actor: alice,
            waitUntil: state =>
                state.alpha_ledger.status === "Refunded" &&
                state.beta_ledger.status === "Refunded",
            test: {
                description:
                    "Should have received the alpha asset after the refund",
                callback: async body => {
                    let refundTxId =
                        body.properties.state.alpha_ledger.refund_tx;

                    let satoshiReceived = await alice.wallet
                        .btc()
                        .moneyReceivedInTx(refundTxId);
                    const satoshiExpected =
                        alphaAssetQuantity - maxFeeInSatoshi;

                    satoshiReceived.should.be.at.least(satoshiExpected);
                },
            },
        },
    ];

    describe("RFC003: Bitcoin for Ether - Both refunded", async () => {
        createTests(alice, bob, steps, "/swaps/rfc003", "/swaps", swapRequest);
    });
    run();
})();
