import express from 'express';
import path from 'path';
import crypto from 'crypto';
import { createServer as createViteServer } from 'vite';
import { createExpressApp } from './src/server/app';

// Ensure server-side session secret configuration
if (!process.env.PHISHGUARD_SESSION_SECRET) {
  if (process.env.NODE_ENV === 'production') {
    console.error('FATAL CONFIGURATION ERROR: PHISHGUARD_SESSION_SECRET server-side environment variable is required in production.');
    process.exit(1);
  } else {
    // Generate ephemeral development-only secret into process environment
    process.env.PHISHGUARD_SESSION_SECRET = crypto.randomBytes(32).toString('hex');
  }
}

async function startServer() {
  const app = createExpressApp();
  const PORT = 3000;

  // Mount Vite development middleware or production static files
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🛡️  PhishGuard Central Security Platform running on http://localhost:${PORT}`);
    console.log(`🚀 API Base URL: http://localhost:${PORT}/api`);
  });
}

startServer().catch((err) => {
  console.error('Fatal server startup error:', err);
  process.exit(1);
});
