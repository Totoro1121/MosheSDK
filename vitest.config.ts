import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('.', import.meta.url));

export default defineConfig({
  test: {
    environment: 'node',
    include: [
      'packages/*/test/**/*.test.ts',
      'test/**/*.test.ts'
    ]
  },
  resolve: {
    alias: {
      '@moshe/spec': fileURLToPath(new URL('./packages/moshe-spec/src/index.ts', import.meta.url)),
      '@moshe/core': fileURLToPath(new URL('./packages/moshe-core/src/index.ts', import.meta.url)),
      '@moshe/store-memory': fileURLToPath(new URL('./packages/moshe-store-memory/src/index.ts', import.meta.url)),
      '@moshe/store-file': fileURLToPath(new URL('./packages/moshe-store-file/src/index.ts', import.meta.url)),
      '@moshe/adapter-generic-tools': fileURLToPath(new URL('./packages/moshe-adapter-generic-tools/src/index.ts', import.meta.url)),
      '@moshe/adapter-openai': fileURLToPath(new URL('./packages/moshe-adapter-openai/src/index.ts', import.meta.url)),
      '@moshe/adapter-anthropic': fileURLToPath(new URL('./packages/moshe-adapter-anthropic/src/index.ts', import.meta.url)),
      '@moshe/sdk': fileURLToPath(new URL('./packages/moshe-sdk-ts/src/index.ts', import.meta.url))
    }
  }
});
