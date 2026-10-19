// Self-contained so that `npx eslint` works without installing plugins.
export default [
    {
        files: ['**/*.js'],
        languageOptions: {
            ecmaVersion: 2022,
            sourceType: 'module',
            globals: {global: 'readonly', console: 'readonly'},
        },
        rules: {
            'no-undef': 'error',
            'no-unused-vars': ['error', {args: 'none'}],
            'no-unreachable': 'error',
            'no-dupe-keys': 'error',
            'no-dupe-class-members': 'error',
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
