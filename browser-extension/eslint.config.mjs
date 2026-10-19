// Self-contained so that `npx eslint` works without installing plugins.
const browserGlobals = Object.fromEntries([
    'window', 'document', 'console', 'chrome', 'URL', 'DOMException', 'btoa', 'atob',
    'structuredClone', 'PublicKeyCredential', 'CredentialsContainer',
    'AuthenticatorAttestationResponse', 'AuthenticatorAssertionResponse',
].map(name => [name, 'readonly']));

export default [
    {
        files: ['**/*.js'],
        languageOptions: {
            ecmaVersion: 2022,
            sourceType: 'script',
            globals: browserGlobals,
        },
        rules: {
            'no-undef': 'error',
            'no-unused-vars': ['error', {args: 'none'}],
            'no-unreachable': 'error',
            'no-dupe-keys': 'error',
            'no-redeclare': 'error',
            'no-const-assign': 'error',
            'no-self-assign': 'error',
            'no-fallthrough': 'error',
            'no-empty': 'error',
            'eqeqeq': 'error',
            'prefer-const': 'error',
            'no-var': 'error',
        },
    },
];
