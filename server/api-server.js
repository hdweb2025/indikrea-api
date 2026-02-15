import http from 'http';
import { expressApp } from './express-app.js';

const PORT = Number(process.env.PORT) || 3000;

const server = http.createServer(expressApp);

server.listen(PORT, '0.0.0.0', () => {
  console.log(`API server listening on port ${PORT}`);
});
