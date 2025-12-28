import { defineConfig, devices } from '@playwright/test';
import { config } from './setup';

export default defineConfig({
  testDir: './specs/browser',
  fullyParallel: false, // OAuth flows have state, run sequentially
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? 'github' : 'list',
  timeout: 60000,

  use: {
    baseURL: config.apiBaseUrl,
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'on-first-retry',
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  // Output folder for test artifacts
  outputDir: './specs/browser/test-results',
});
