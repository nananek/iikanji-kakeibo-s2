// E2E 用の静的配信 + API プロキシサーバー (Node 組み込みのみ、依存なし)。
//
// dist/ を静的配信し、API パス (/auth, /sync, /health) を Rust サーバー (E2E_BACKEND) へ
// メソッド/ヘッダ/ボディごと転送する。これにより SPA は同一オリジン (相対 URL) でアクセスでき、
// CORS もサーバー側変更も不要。Rust サーバーと Postgres は本サーバーの外で起動しておく。
//
// 環境変数: E2E_PORT (default 8080) / E2E_BACKEND (default http://127.0.0.1:3000) / E2E_DIST (default dist)

import http from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { extname, join, normalize, resolve, sep } from 'node:path';

const PORT = Number(process.env.E2E_PORT ?? 8080);
const BACKEND = new URL(process.env.E2E_BACKEND ?? 'http://127.0.0.1:3000');
const DIST = resolve(process.env.E2E_DIST ?? 'dist');
const API_PREFIXES = ['/auth', '/sync', '/health'];

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.wasm': 'application/wasm',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.ico': 'image/x-icon',
  '.svg': 'image/svg+xml',
};

function isApiPath(pathname) {
  return API_PREFIXES.some((p) => pathname === p || pathname.startsWith(p + '/'));
}

async function serveStatic(res, pathname) {
  let rel = decodeURIComponent(pathname);
  if (rel === '/' || rel === '') rel = '/index.html';
  const filePath = normalize(join(DIST, rel));
  // ディレクトリトラバーサル防止 (兄弟ディレクトリ dist-evil 等の prefix 誤判定も排除)。
  if (filePath !== DIST && !filePath.startsWith(DIST + sep)) {
    res.writeHead(403).end('forbidden');
    return;
  }
  try {
    const s = await stat(filePath);
    if (s.isDirectory()) throw new Error('is dir');
    const data = await readFile(filePath);
    res.writeHead(200, { 'Content-Type': MIME[extname(filePath)] ?? 'application/octet-stream' });
    res.end(data);
  } catch {
    // SPA fallback (将来のクライアントルーティング用)。
    try {
      const data = await readFile(join(DIST, 'index.html'));
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(data);
    } catch {
      res.writeHead(404).end('not found');
    }
  }
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://127.0.0.1:${PORT}`);
  if (isApiPath(url.pathname)) {
    const proxyReq = http.request(
      {
        hostname: BACKEND.hostname,
        port: BACKEND.port,
        path: req.url,
        method: req.method,
        headers: { ...req.headers, host: BACKEND.host },
      },
      (proxyRes) => {
        res.writeHead(proxyRes.statusCode ?? 502, proxyRes.headers);
        proxyRes.pipe(res);
      },
    );
    proxyReq.on('error', (e) => {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `proxy error: ${e.message}` }));
    });
    req.pipe(proxyReq);
    return;
  }
  serveStatic(res, url.pathname).catch((e) => {
    res.writeHead(500).end(String(e));
  });
});

server.listen(PORT, '127.0.0.1', () => {
  // eslint-disable-next-line no-console
  console.log(`e2e-server: :${PORT} static=${DIST} proxy ${API_PREFIXES.join(',')} -> ${BACKEND.origin}`);
});
