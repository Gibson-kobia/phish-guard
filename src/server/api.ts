/**
 * Vercel Serverless Function Source Entrypoint
 * 
 * Source entrypoint for PhishGuard Express API.
 * Compiles via esbuild into a self-contained, standalone api/index.js bundle for Vercel deployment.
 */

import { createExpressApp } from './app';

const app = createExpressApp();

export default app;
