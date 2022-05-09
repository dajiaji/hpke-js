export default {
  preset: 'ts-jest',
  clearMocks: true,
  testMatch: ['**/test/**/*.test.ts'],
  testEnvironment: 'node',
  coverageReporters: ['lcov', 'text'],
  globals: {
    'ts-jest': {
      isolatedModules: true,
    },
  },
};
