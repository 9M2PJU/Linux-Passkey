// Linux Passkey: content script in the extension's isolated world.
//
// page.js runs in the page's own world, where it can replace
// navigator.credentials but cannot reach extension APIs; this script passes
// its messages to the background script and the answers back.

'use strict';

window.addEventListener('message', event => {
    const data = event.data;
    if (event.source !== window || data?.linuxPasskey !== 'request')
        return;
    const reply = message => window.postMessage({linuxPasskey: 'reply', id: data.id, ...message}, '*');
    let sent;
    try {
        sent = chrome.runtime.sendMessage({
            id: data.id,
            op: data.op,
            options: data.options,
            target: data.target,
        });
    } catch (e) {
        // The extension was updated or removed since this page loaded.
        reply({error: {name: 'UnavailableError', message: String(e)}});
        return;
    }
    sent.then(
        answer => reply(answer ?? {error: {name: 'UnavailableError', message: 'no answer'}}),
        e => reply({error: {name: 'UnavailableError', message: String(e)}}));
});
