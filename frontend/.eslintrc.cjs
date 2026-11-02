module.exports = {
  root: true,
  // Without this, `npm run lint` after a `npm run build` lints the minified
  // bundle in dist/ and reports hundreds of rules-of-hooks errors against it.
  ignorePatterns: ['dist', 'node_modules'],
  env: { browser: true, es2021: true, node: true },
  extends: ['eslint:recommended', 'plugin:react/recommended', 'plugin:react-hooks/recommended'],
  parserOptions: { ecmaVersion: 'latest', sourceType: 'module', ecmaFeatures: { jsx: true } },
  settings: { react: { version: 'detect' } },
  rules: {
    'react/react-in-jsx-scope': 'off',
    'react/prop-types': 'off',
  },
}
