// Linux Passkey: runs in the page's own world, before the page's scripts.
//
// Makes this computer a platform authenticator, as Windows Hello is on
// Windows: navigator.credentials.create() and get() are answered by
// passkeyd, and PublicKeyCredential reports a user-verifying platform
// authenticator. Anything meant for another authenticator goes to the
// browser's own implementation unchanged: a site asking for a security key
// or a phone, a sign-in with no passkey stored here, conditional (autofill)
// requests, and every case where passkeyd is not available.

(() => {
    'use strict';

    if (!window.isSecureContext || !window.PublicKeyCredential || !window.CredentialsContainer)
        return;

    const container = CredentialsContainer.prototype;
    const nativeCreate = container.create;
    const nativeGet = container.get;
    const nativeUvpaa = PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable;
    const nativeCapabilities = PublicKeyCredential.getClientCapabilities;

    // Errors that hand the request to the browser instead of failing it.
    const FALLBACK = new Set([
        'NotSupportedError', 'SecurityError', 'UnavailableError', 'TypeError', 'UnknownError',
    ]);

    // -- messages to bridge.js ---------------------------------------------

    let sequence = 0;
    const waiting = new Map();

    window.addEventListener('message', event => {
        const data = event.data;
        if (event.source !== window || data?.linuxPasskey !== 'reply')
            return;
        const resolve = waiting.get(data.id);
        if (resolve) {
            waiting.delete(data.id);
            resolve(data);
        }
    });

    function send(op, fields = {}) {
        const id = ++sequence;
        const reply = new Promise(resolve => {
            waiting.set(id, resolve);
            window.postMessage({linuxPasskey: 'request', id, op, ...fields}, '*');
        });
        return {id, reply};
    }

    let ready = null;
    function platformReady() {
        ready ??= send('status').reply.then(
            answer => answer.result?.ready === true,
            () => false);
        return ready;
    }

    // -- base64url and the WebAuthn JSON forms ------------------------------

    const isBuffer = value =>
        ArrayBuffer.isView(value) || Object.prototype.toString.call(value) === '[object ArrayBuffer]';

    function toBase64url(value) {
        const bytes = ArrayBuffer.isView(value)
            ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
            : new Uint8Array(value);
        let binary = '';
        for (const byte of bytes)
            binary += String.fromCharCode(byte);
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function fromBase64url(text) {
        const binary = atob(text.replace(/-/g, '+').replace(/_/g, '/'));
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++)
            bytes[i] = binary.charCodeAt(i);
        return bytes.buffer;
    }

    function toJSONValue(value) {
        if (isBuffer(value))
            return toBase64url(value);
        if (Array.isArray(value))
            return value.map(toJSONValue);
        if (value && typeof value === 'object') {
            const out = {};
            for (const [key, item] of Object.entries(value)) {
                if (item !== undefined)
                    out[key] = toJSONValue(item);
            }
            return out;
        }
        return value;
    }

    function define(object, values, enumerable) {
        for (const [key, value] of Object.entries(values))
            Object.defineProperty(object, key, {value, enumerable, configurable: true});
        return object;
    }

    // Real PublicKeyCredential objects cannot be constructed from script, so
    // the results inherit from the real prototypes (instanceof works) and
    // carry their values as own properties.
    function makeCredential(json, response) {
        const credential = Object.create(PublicKeyCredential.prototype);
        define(credential, {
            id: json.id,
            rawId: fromBase64url(json.rawId),
            type: 'public-key',
            authenticatorAttachment: json.authenticatorAttachment,
            response,
        }, true);
        define(credential, {
            getClientExtensionResults: () => structuredClone(json.clientExtensionResults ?? {}),
            toJSON: () => structuredClone(json),
        }, false);
        return credential;
    }

    function registration(json) {
        const r = json.response;
        const response = Object.create(AuthenticatorAttestationResponse.prototype);
        define(response, {
            clientDataJSON: fromBase64url(r.clientDataJSON),
            attestationObject: fromBase64url(r.attestationObject),
        }, true);
        define(response, {
            getTransports: () => [...(r.transports ?? [])],
            getAuthenticatorData: () => fromBase64url(r.authenticatorData),
            getPublicKey: () => (r.publicKey ? fromBase64url(r.publicKey) : null),
            getPublicKeyAlgorithm: () => r.publicKeyAlgorithm,
            toJSON: () => structuredClone(r),
        }, false);
        return makeCredential(json, response);
    }

    function assertion(json) {
        const r = json.response;
        const response = Object.create(AuthenticatorAssertionResponse.prototype);
        define(response, {
            clientDataJSON: fromBase64url(r.clientDataJSON),
            authenticatorData: fromBase64url(r.authenticatorData),
            signature: fromBase64url(r.signature),
            userHandle: r.userHandle ? fromBase64url(r.userHandle) : null,
        }, true);
        define(response, {toJSON: () => structuredClone(r)}, false);
        return makeCredential(json, response);
    }

    // -- ceremonies -----------------------------------------------------------

    function abortReason(signal) {
        return signal.reason ?? new DOMException('The operation was aborted.', 'AbortError');
    }

    async function ceremony(op, publicKey, signal) {
        if (signal?.aborted)
            throw abortReason(signal);
        const {id, reply} = send(op, {options: toJSONValue(publicKey)});
        if (!signal)
            return reply;
        let onAbort;
        const aborted = new Promise((_, reject) => {
            onAbort = () => {
                send('cancel', {target: id});
                reject(abortReason(signal));
            };
            signal.addEventListener('abort', onAbort, {once: true});
        });
        try {
            return await Promise.race([reply, aborted]);
        } finally {
            signal.removeEventListener('abort', onAbort);
        }
    }

    function settle(answer, build, fallback) {
        if (answer.error) {
            if (FALLBACK.has(answer.error.name))
                return fallback();
            throw new DOMException(answer.error.message, answer.error.name);
        }
        return build(answer.result);
    }

    container.create = function create(options) {
        const publicKey = options?.publicKey;
        if (!publicKey || !isBuffer(publicKey.challenge))
            return nativeCreate.apply(this, arguments);
        const fallback = () => nativeCreate.apply(this, arguments);
        return ceremony('create', publicKey, options.signal)
            .then(answer => settle(answer, registration, fallback));
    };

    container.get = function get(options) {
        const publicKey = options?.publicKey;
        // Conditional (autofill) requests stay with the browser, which owns
        // the autofill list.
        if (!publicKey || !isBuffer(publicKey.challenge) || options.mediation === 'conditional')
            return nativeGet.apply(this, arguments);
        const fallback = () => nativeGet.apply(this, arguments);
        return send('has', {options: toJSONValue(publicKey)}).reply.then(found => {
            if (found.result !== true)
                return fallback();
            return ceremony('get', publicKey, options.signal)
                .then(answer => settle(answer, assertion, fallback));
        });
    };

    PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable =
        async function isUserVerifyingPlatformAuthenticatorAvailable() {
            if (await platformReady())
                return true;
            return nativeUvpaa.call(PublicKeyCredential);
        };

    if (nativeCapabilities) {
        PublicKeyCredential.getClientCapabilities = async function getClientCapabilities() {
            const capabilities = await nativeCapabilities.call(PublicKeyCredential);
            if (await platformReady()) {
                capabilities.passkeyPlatformAuthenticator = true;
                capabilities.userVerifyingPlatformAuthenticator = true;
            }
            return capabilities;
        };
    }
})();
