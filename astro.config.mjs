// @ts-check
import { defineConfig } from 'astro/config';

// Static output (default). All DNS lookups run client-side over DNS-over-HTTPS,
// so no adapter or serverless function is needed.
export default defineConfig({
  site: 'https://lildmarc.netlify.app',
});
