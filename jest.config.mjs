export default {
  preset: 'ts-jest',
  clearMocks: true,
  testMatch: ['**/test/**/*.test.ts'],
  testEnvironment: 'jsdom',
  coverageReporters: ['lcov', 'text'],
  globals: {
    'ts-jest': {
      isolatedModules: true,
    },
  },
};
