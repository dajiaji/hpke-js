export default {
  preset: 'ts-jest',
  clearMocks: true,
  testMatch: ['**/test/**/*.test.ts'],
  collectCoverage: true,
  collectCoverageFrom: ['src/**/{!(mod),}.ts'],
  testTimeout: 30000,
  testEnvironment: 'node',
  coverageReporters: ['lcov', 'text'],
  globals: {
    'ts-jest': {
      isolatedModules: true,
    },
  },
};
