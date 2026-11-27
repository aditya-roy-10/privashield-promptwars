import { defineConfig } from 'vite';

const PRODUCTION_CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "worker-src 'self'",
  "connect-src 'none'",
  "font-src 'self'",
  "base-uri 'self'",
  "form-action 'none'",
  "object-src 'none'"
].join('; ');

function productionCspPlugin() {
  return {
    name: 'privashield-production-csp',
    apply: 'build',
    transformIndexHtml(html) {
      return html.replace(
        '<meta name="color-scheme" content="dark light" />',
        `<meta name="color-scheme" content="dark light" />\n<meta http-equiv="Content-Security-Policy" content="${PRODUCTION_CSP}" />`
      );
    }
  };
}

export default defineConfig({
  plugins: [productionCspPlugin()],
  preview: {
    headers: {
      'Content-Security-Policy': `${PRODUCTION_CSP}; frame-ancestors 'none'`,
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer'
    }
  }
});
