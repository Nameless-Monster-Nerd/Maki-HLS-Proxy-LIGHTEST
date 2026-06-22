const crypto = require('crypto');

const PROXY_HOST = 'http://localhost:80';

// Set to the same 64-hex value as ENCRYPTION_KEY on the proxy.
// Leave empty string to use plain (unencrypted) URL params.
const ENCRYPTION_KEY = '';

const url = 'https://content.jwplatform.com/manifests/yp34SRmf.m3u8';
const headers = {
  "Origin": "https://developer-tools.jwplayer.com/stream-tester",
  "Referer": "https://developer-tools.jwplayer.com/stream-tester/",
  "Host": "developer-tools.jwplayer.com"
};

function b64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function encryptPayload(url, headers, keyHex) {
  const key = Buffer.from(keyHex, 'hex');
  if (key.length !== 32) throw new Error('ENCRYPTION_KEY must be 64 hex chars (32 bytes)');
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const json = JSON.stringify({ u: url, h: headers });
  const ct = Buffer.concat([cipher.update(json, 'utf8'), cipher.final()]);
  return b64url(Buffer.concat([iv, ct]));
}

let proxyUrl;
if (ENCRYPTION_KEY) {
  const token = encryptPayload(url, headers, ENCRYPTION_KEY);
  proxyUrl = `${PROXY_HOST}/m3u8-proxy.m3u8?p=${encodeURIComponent(token)}`;
} else {
  proxyUrl = `${PROXY_HOST}/m3u8-proxy.m3u8?url=${encodeURIComponent(url)}&headers=${encodeURIComponent(JSON.stringify(headers))}`;
}

console.log(proxyUrl);
