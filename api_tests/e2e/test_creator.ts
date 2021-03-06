import {
    AcceptRequestBody,
    Action,
    ActionKind,
    getMethod,
    Method,
} from "../lib/comit";
import { request, expect } from "chai";
import { Actor } from "../lib/actor";
import * as URI from "urijs";
import "chai/register-should";
import "../lib/setupChai";
import { EmbeddedRepresentationSubEntity } from "../gen/siren";

export interface Test {
    /**
     * To be triggered once an action is executed
     *
     * @property description: the description to use for the callback
     * @property callback: an (async) function take the body of a swap state response as parameter
     * @property timeout: if set, overrides the Mocha default timeout.
     */
    description: string;
    callback: (body: any) => Promise<void>;
    timeout?: number;
}

export interface ActionTrigger {
    /**
     * Triggers an action and do the callback
     *
     * @property actor: the actor for which/that triggers the action
     * @property action: the name of the action that will be extracted from the COMIT-rs HTTP API
     * @property requestBody: the requestBody to pass if the action requires a POST call on the COMIT-rs HTTP API
     * @property uriQuery: the GET parameters to pass if the action requires a GET call on the COMIT-rs HTTP API
     * @property timeout: the time to allow the action to be executed
     * @property state: a predicate passed on the test after the action is executed
     * @property test: a test to be executed after the action is executed, the body of a swap request is passed only if `state` property is set
     *
     */
    actor: Actor;
    action?: ActionKind;
    requestBody?: AcceptRequestBody;
    uriQuery?: object;
    state?: (state: any) => boolean;
    test?: Test;
}

async function getAction(
    location: string,
    actionTrigger: ActionTrigger
): Promise<[string, Action]> {
    location.should.not.be.empty;

    const body = await actionTrigger.actor.pollComitNodeUntil(
        location,
        body =>
            body.links.findIndex(link =>
                link.rel.includes(actionTrigger.action)
            ) != -1
    );

    let href = body.links.find(link => link.rel.includes(actionTrigger.action))
        .href;

    expect(href).to.not.be.empty;

    if (actionTrigger.uriQuery) {
        let hrefUri = new URI(href);
        hrefUri.addQuery(actionTrigger.uriQuery);
        href = hrefUri.toString();
    }

    if (getMethod(actionTrigger.action) === Method.Get) {
        const res = await request(actionTrigger.actor.comit_node_url()).get(
            href
        );
        res.should.have.status(200);
        let payload = res.body;
        return [href, payload];
    }
    return [href, null];
}

async function executeAction(
    actor: Actor,
    actionTrigger: ActionTrigger,
    actionHref?: string,
    actionDirective?: Action
) {
    const method = getMethod(actionTrigger.action);

    switch (method) {
        case Method.Get:
            await actor.do(actionDirective);
            break;
        case Method.Post:
            const res = await request(actor.comit_node_url())
                .post(actionHref)
                .send(actionTrigger.requestBody);

            res.should.have.status(200);
            break;
        default:
            throw new Error(`unknown method: ${method}`);
    }
}

export async function createTests(
    alice: Actor,
    bob: Actor,
    actions: ActionTrigger[],
    initialUrl: string,
    listUrl: string,
    initialRequest: object
) {
    // This may need to become more generic at a later stage
    // However, it would be unnecessary pre-optimisation now.
    let swapLocations: { [key: string]: string } = {};

    it(
        "[alice] Should be able to make a request via HTTP api to " +
            initialUrl,
        async () => {
            let res: ChaiHttp.Response = await request(alice.comit_node_url())
                .post(initialUrl)
                .send(initialRequest);
            res.should.have.status(201);
            const swapLocation: string = res.header.location;
            swapLocation.should.not.be.empty;
            swapLocations["alice"] = swapLocation;
        }
    );

    it("[bob] Shows the Swap as IN_PROGRESS in " + listUrl, async () => {
        let swapsEntity = await bob.pollComitNodeUntil(
            listUrl,
            body => body.entities.length > 0
        );

        let swapEntity = swapsEntity
            .entities[0] as EmbeddedRepresentationSubEntity;

        expect(swapEntity.properties).to.have.property("protocol", "rfc003");
        expect(swapEntity.properties).to.have.property("status", "IN_PROGRESS");

        let selfLink = swapEntity.links.find(link => link.rel.includes("self"));

        expect(selfLink).to.not.be.undefined;

        swapLocations["bob"] = selfLink.href;
    });

    while (actions.length !== 0) {
        let action = actions.shift();
        let actionHref: string = null;
        let actionDirective: Action = null;
        if (action.action) {
            it(`[${action.actor.name}] Can get the ${
                action.action
            } action`, async function() {
                this.timeout(5000);
                [actionHref, actionDirective] = await getAction(
                    swapLocations[action.actor.name],
                    action
                );
            });

            it(`[${action.actor.name}] Can execute the ${
                action.action
            } action`, async function() {
                if (action.action == ActionKind.Refund) {
                    this.timeout(30000);
                } else {
                    this.timeout(5000);
                }

                await executeAction(
                    action.actor,
                    action,
                    actionHref,
                    actionDirective
                );
            });
        }

        let body: any = null;
        if (action.state) {
            it(`[${
                action.actor.name
            }] transitions to correct state`, async function() {
                this.timeout(10000);
                body = await action.actor.pollComitNodeUntil(
                    swapLocations[action.actor.name],
                    body => action.state(body.properties.state)
                );
            });
        }

        const test = action.test;
        if (test) {
            it(
                "[" + action.actor.name + "] " + test.description,
                async function() {
                    if (test.timeout) {
                        this.timeout(test.timeout);
                    }

                    return test.callback(body);
                }
            );
        }
    }
}
