module.exports = {
  root: true,
  extends: ['@react-native', 'prettier'],
  rules: {
    'react/react-in-jsx-scope': 'off',
    'prettier/prettier': [
      'error',
      {
        arrowParens: 'avoid',
        bracketSameLine: true,
        bracketSpacing: false,
        singleQuote: true,
        trailingComma: 'all',
      },
    ],
  },
};
