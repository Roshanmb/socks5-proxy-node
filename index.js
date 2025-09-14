// index.js
'use strict';

const net = require('net');
const fs = require('fs');
const { isIP } = net;

// Load config: defaults -> config.json (if present) -> env overrides
let config = {
  host: process.env.HOST || '0.0.0.0',
  port: Number(process.env.PORT || 1080),
  user: process.env.SOCKS_USER || 'user',
  pass: process.env.SOCKS_PASS || 'pass'
};

try {
  const cfgFile = JSON.parse(fs.readFileSync('./config.json', 'utf8'));
  config = { ...config, ...cfgFile };
  console.log('[config] loaded config.json');
} catch (e) {
  // no config.json is fine
}

console.log(`[info] socks5 proxy starting on ${config.host}:${config.port}`);
console.log(`[info] authentication username='${config.user}'`);

/**
 * Helper to create a timestamped log
 */
function now() {
  return new Date().toISOString();
}

/**
 * Send a SOCKS5 reply to the client
 * rep: reply code (0x00 success, others error)
 * bound: { addr, port } optional
 */
function sendSocks5Reply(socket, rep, bound) {
  bound = bound || { addr: '0.0.0.0', port: 0 };
  let atyp;
  const addr = bound.addr;
  const port = bound.port || 0;

  const ipType = isIP(addr); // 0,4,6
  if (ipType === 4) {
    atyp = 0x01;
    const addrBuf = Buffer.from(addr.split('.').map(Number));
    const portBuf = Buffer.alloc(2);
    portBuf.writeUInt16BE(port, 0);
    const buf = Buffer.concat([Buffer.from([0x05, rep, 0x00, atyp]), addrBuf, portBuf]);
    socket.write(buf);
  } else if (ipType === 6) {
    atyp = 0x04;
    const addrParts = addr.split(':').map(p => parseInt(p || '0', 16));
    const addrBuf = Buffer.alloc(16);
    for (let i = 0; i < 8; i++) {
      addrBuf.writeUInt16BE(addrParts[i] || 0, i * 2);
    }
    const portBuf = Buffer.alloc(2);
    portBuf.writeUInt16BE(port, 0);
    const buf = Buffer.concat([Buffer.from([0x05, rep, 0x00, atyp]), addrBuf, portBuf]);
    socket.write(buf);
  } else {
    // domain
    atyp = 0x03;
    const domainBuf = Buffer.from(addr);
    const len = Buffer.from([domainBuf.length]);
    const portBuf = Buffer.alloc(2);
    portBuf.writeUInt16BE(port, 0);
    const buf = Buffer.concat([Buffer.from([0x05, rep, 0x00, atyp]), len, domainBuf, portBuf]);
    socket.write(buf);
  }
}

/**
 * Parse an IPv6 buffer (16 bytes) into textual representation (no compression)
 */
function ipv6BufToString(buf) {
  const parts = [];
  for (let i = 0; i < 16; i += 2) {
    parts.push(buf.readUInt16BE(i).toString(16));
  }
  return parts.join(':');
}

/**
 * Server
 */
const server = net.createServer((client) => {
  const clientRemote = `${client.remoteAddress}:${client.remotePort}`;
  console.log(`[${now()}] New client ${clientRemote}`);

  let state = 'greeting';
  let buffer = Buffer.alloc(0);

  function consume(n) {
    const out = buffer.slice(0, n);
    buffer = buffer.slice(n);
    return out;
  }

  client.on('data', (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    try { processBuffer(); } catch (err) {
      console.warn(`[${now()}] Error processing client (${clientRemote}):`, err && err.message);
      client.destroy();
    }
  });

  client.on('error', (err) => {
    console.warn(`[${now()}] Client ${clientRemote} error: ${err.message}`);
  });

  client.on('close', () => {
    console.log(`[${now()}] Client ${clientRemote} disconnected`);
  });

  function processBuffer() {
    while (true) {
      if (state === 'greeting') {
        // Need at least 2 bytes (VER, NMETHODS)
        if (buffer.length < 2) return;
        const ver = buffer[0];
        const nmethods = buffer[1];
        if (ver !== 0x05) {
          console.warn(`[${now()}] Unsupported SOCKS version ${ver} from ${clientRemote}`);
          client.destroy();
          return;
        }
        if (buffer.length < 2 + nmethods) return; // wait for full methods
        const methods = consume(2 + nmethods).slice(2);
        // We require username/password (0x02). If client doesn't offer it, reject.
        if (methods.includes(0x02)) {
          // SELECT username/password
          client.write(Buffer.from([0x05, 0x02]));
          state = 'auth';
          continue;
        } else {
          client.write(Buffer.from([0x05, 0xff])); // no acceptable method
          client.destroy();
          return;
        }
      } else if (state === 'auth') {
        // Username/password subnegotiation (RFC1929)
        // Need at least 2 bytes (VER, ULEN)
        if (buffer.length < 2) return;
        const ver = buffer[0];
        if (ver !== 0x01) { client.destroy(); return; }
        const ulen = buffer[1];
        if (buffer.length < 2 + ulen + 1) return; // need PLEN at least
        const uname = buffer.slice(2, 2 + ulen).toString();
        const plen = buffer[2 + ulen];
        if (buffer.length < 2 + ulen + 1 + plen) return;
        const passwd = buffer.slice(2 + ulen + 1, 2 + ulen + 1 + plen).toString();
        // consume the auth bytes
        consume(2 + ulen + 1 + plen);
        // validate
        if (uname === config.user && passwd === config.pass) {
          client.write(Buffer.from([0x01, 0x00])); // success
          state = 'request';
          continue;
        } else {
          client.write(Buffer.from([0x01, 0x01])); // failure
          client.destroy();
          return;
        }
      } else if (state === 'request') {
        // Need at least 4 bytes for header
        if (buffer.length < 4) return;
        const header = buffer.slice(0, 4);
        const ver = header[0], cmd = header[1], rsv = header[2], atyp = header[3];
        if (ver !== 0x05) { client.destroy(); return; }
        if (cmd !== 0x01) {
          // Only CONNECT supported
          sendSocks5Reply(client, 0x07); // Command not supported
          client.destroy();
          return;
        }
        if (atyp === 0x01) {
          // IPv4: 4 bytes addr + 2 bytes port
          if (buffer.length < 4 + 4 + 2) return;
          // consume header
          consume(4);
          const addrBytes = consume(4);
          const portBytes = consume(2);
          const destHost = addrBytes.join('.');
          const destPort = portBytes.readUInt16BE(0);
          handleConnect(destHost, destPort);
          return; // handleConnect will set up pipes; after that we don't stay in this loop
        } else if (atyp === 0x03) {
          // Domain: 1 byte len, then domain, then 2 bytes port
          if (buffer.length < 5) return; // need at least domain len
          const domainLen = buffer[4];
          if (buffer.length < 4 + 1 + domainLen + 2) return;
          consume(4); // header
          const lenBuf = consume(1);
          const domainBuf = consume(domainLen);
          const portBuf = consume(2);
          const destHost = domainBuf.toString();
          const destPort = portBuf.readUInt16BE(0);
          handleConnect(destHost, destPort);
          return;
        } else if (atyp === 0x04) {
          // IPv6: 16 bytes addr + 2 bytes port
          if (buffer.length < 4 + 16 + 2) return;
          consume(4);
          const addrBuf = consume(16);
          const portBuf = consume(2);
          const destHost = ipv6BufToString(addrBuf);
          const destPort = portBuf.readUInt16BE(0);
          handleConnect(destHost, destPort);
          return;
        } else {
          sendSocks5Reply(client, 0x08); // address type not supported
          client.destroy();
          return;
        }
      } else {
        // In relay state, let piping handle data; nothing to parse here
        return;
      }
    }
  }

  function handleConnect(destHost, destPort) {
    console.log(`[${now()}] ${clientRemote} -> CONNECT ${destHost}:${destPort}`);
    // Create remote connection
    const remote = net.createConnection({ host: destHost, port: destPort });

    // on connect: reply success and start piping
    remote.once('connect', () => {
      const localAddr = remote.localAddress || '0.0.0.0';
      const localPort = remote.localPort || 0;
      sendSocks5Reply(client, 0x00, { addr: localAddr, port: localPort });
      // If there's any leftover data (very unlikely because we consumed request bytes), forward it:
      if (buffer.length > 0) {
        remote.write(buffer);
        buffer = Buffer.alloc(0);
      }
      // Start tunneling
      client.pipe(remote);
      remote.pipe(client);
      state = 'relay';
      // Log established tunnel
      console.log(`[${now()}] Tunnel established ${clientRemote} <-> ${destHost}:${destPort}`);
    });

    remote.on('error', (err) => {
      console.warn(`[${now()}] Remote connection error to ${destHost}:${destPort} : ${err.message}`);
      // send general failure
      sendSocks5Reply(client, 0x01);
      client.destroy();
      remote.destroy();
    });

    // If client closes, close remote
    client.on('close', () => {
      remote.destroy();
    });
    remote.on('close', () => {
      client.destroy();
    });
  }
});

server.on('error', (err) => {
  console.error('[server] error', err);
});

server.listen(config.port, config.host, () => {
  console.log(`[${now()}] Listening on ${config.host}:${config.port}`);
});
