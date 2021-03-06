import { use, request } from "chai";
import { Transaction, TransactionReceipt } from "web3-core";
import * as toml from "toml";
import * as fs from "fs";
import { TestConfig } from "./actor";
import chaiHttp = require("chai-http");

use(chaiHttp);

export interface IdMatchResponse {
    query: any;
    matches: { id: string }[];
}

export interface EthereumTransactionResponse {
    query: any;
    matches: EthereumMatch[];
}

export interface EthereumMatch {
    transaction: Transaction;
    receipt: TransactionReceipt;
}

export interface MetaBtsieveConfig {
    host: string;
    config_dir: string;
    env: { [key: string]: string };
}

export class Btsieve {
    host: string;
    port: number;

    constructor(name: string, testConfig: TestConfig, root: string) {
        const metaBtsieveConfig = testConfig.btsieve;
        if (!metaBtsieveConfig) {
            throw new Error("btsieve configuration is needed");
        }

        this.host = metaBtsieveConfig[name].host;
        let btsieveConfig = toml.parse(
            fs.readFileSync(
                root +
                    "/" +
                    metaBtsieveConfig[name].config_dir +
                    "/default.toml",
                "utf8"
            )
        );
        this.port = btsieveConfig.http_api.port_bind;
    }

    url() {
        return "http://" + this.host + ":" + this.port;
    }

    absoluteLocation(relative_location: string) {
        return this.url() + relative_location;
    }

    pollUntilMatches(query_url: string) {
        return new Promise((final_res, rej) => {
            request(query_url)
                .get("")
                .end((err, res) => {
                    if (err) {
                        return rej(err);
                    }
                    res.should.have.status(200);
                    if (res.body.matches.length !== 0) {
                        final_res(res.body);
                    } else {
                        setTimeout(async () => {
                            const result = await this.pollUntilMatches(
                                query_url
                            );
                            final_res(result);
                        }, 200);
                    }
                });
        });
    }
}
