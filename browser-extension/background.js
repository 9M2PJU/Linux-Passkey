// Linux Passkey: background script.
//
// Relays WebAuthn requests from pages (through bridge.js) to the native
// messaging host, which hands them to passkeyd. This is where the origin is
// decided: it comes from the browser's record of the sending frame, never
// from the page, and passkeyd builds clientDataJSON and checks the RP ID
// against it.

'use strict';

const HOST = 'io.github.haythmkenway.passkey';

let port = null;
let nextId = 1;
const replies = new Map(); // native id -> resolve
const ceremonies = new Map(); // "tab:frame:page id" -> native id

function connect() {
    port = chrome.runtime.connectNative(HOST);
    port.onMessage.addListener(message => {
        const resolve = replies.get(message.id);
        if (resolve) {
            replies.delete(message.id);
            resolve(message);
        }
    });
    port.onDisconnect.addListener(() => {
        const reason = chrome.runtime.lastError?.message ?? 'the native host exited';
        port = null;
        for (const [id, resolve] of replies)
            resolve({id, error: {name: 'UnavailableError', message: reason}});
        replies.clear();
    });
}

function callHost(message) {
    const id = nextId++;
    const reply = new Promise(resolve => {
        replies.set(id, resolve);
        try {
            if (!port)
                connect();
            port.postMessage({...message, id});
        } catch (e) {
            replies.delete(id);
            resolve({id, error: {name: 'UnavailableError', message: String(e)}});
        }
    });
    return {id, reply};
}

function senderOrigins(sender) {
    const origin = sender.origin ?? new URL(sender.url).origin;
    const top = sender.tab?.url ? new URL(sender.tab.url).origin : origin;
    return {origin, top};
}

async function handle(request, sender) {
    if (sender.id !== chrome.runtime.id || !sender.url)
        return {error: {name: 'NotAllowedError', message: 'unknown sender'}};
    const {origin, top} = senderOrigins(sender);
    // A cross-origin frame may only use WebAuthn if the page allowed it with
    // a permissions policy, which an extension cannot see; let the browser
    // decide those.
    if (top !== origin)
        return {error: {name: 'NotSupportedError', message: 'cross-origin frame'}};

    const key = `${sender.tab?.id}:${sender.frameId}:${request.id}`;
    switch (request.op) {
    case 'status':
        return callHost({op: 'status'}).reply;
    case 'has':
        return callHost({op: 'has', origin, options: request.options}).reply;
    case 'create':
    case 'get': {
        const {id, reply} = callHost({op: request.op, origin, options: request.options});
        ceremonies.set(key, id);
        try {
            return await reply;
        } finally {
            ceremonies.delete(key);
        }
    }
    case 'cancel': {
        const target = ceremonies.get(`${sender.tab?.id}:${sender.frameId}:${request.target}`);
        if (target !== undefined)
            callHost({op: 'cancel', target});
        return {result: null};
    }
    }
    return {error: {name: 'TypeError', message: 'unknown operation'}};
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    handle(request, sender).then(sendResponse, e =>
        sendResponse({error: {name: 'UnavailableError', message: String(e)}}));
    return true; // the response is sent asynchronously
});
