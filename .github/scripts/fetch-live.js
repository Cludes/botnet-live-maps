#!/usr/bin/env node
// =============================================================
//  fetch-live.js
//  Fetches Feodo Tracker C2 blocklist, geo-enriches each IP
//  via ip-api.com batch endpoint, writes data/live.json.
//
//  No API keys required - both services are free/open.
// =============================================================

'use strict';

const https = require('https');
const http  = require('http');
const fs    = require('fs');
const path  = require('path');

const FEODO_URL   = 'https://feodotracker.abuse.ch/downloads/ipblocklist.json';
const IPAPI_URL   = 'http://ip-api.com/batch?fields=status,lat,lon,country,countryCode,isp,query';
const OUT_FILE    = path.join(__dirname, '../../data/live.json');

// Batch size limit for ip-api.com free tier
const BATCH_SIZE  = 100;
// Delay between batches to stay under 45 req/min rate limit
const BATCH_DELAY = 1500; // ms

function get(url) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    mod.get(url, res => {
      if (res.statusCode !== 200) {
        reject(new Error(`GET ${url} -> HTTP ${res.statusCode}`));
        res.resume();
        return;
      }
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(body)); }
        catch (e) { reject(new Error(`JSON parse error: ${e.message}`)); }
      });
    }).on('error', reject);
  });
}

function post(url, payload) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(payload);
    const opts = Object.assign(require('url').parse(url), {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    });
    const mod = url.startsWith('https') ? https : http;
    const req = mod.request(opts, res => {
      if (res.statusCode !== 200) {
        reject(new Error(`POST ${url} -> HTTP ${res.statusCode}`));
        res.resume();
        return;
      }
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(new Error(`JSON parse error: ${e.message}`)); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function chunks(arr, size) {
  const result = [];
  for (let i = 0; i < arr.length; i += size) result.push(arr.slice(i, i + size));
  return result;
}

async function geolocate(ips) {
  const geoMap = {};
  const batches = chunks(ips, BATCH_SIZE);

  for (let i = 0; i < batches.length; i++) {
    if (i > 0) await sleep(BATCH_DELAY);

    const payload = batches[i].map(ip => ({ query: ip }));
    try {
      const results = await post(IPAPI_URL, payload);
      for (const r of results) {
        if (r.status === 'success') {
          geoMap[r.query] = { lat: r.lat, lng: r.lon, country: r.countryCode, isp: r.isp };
        }
      }
      console.log(`  Geolocated batch ${i + 1}/${batches.length} (${results.filter(r => r.status === 'success').length} ok)`);
    } catch (err) {
      console.warn(`  Geolocation batch ${i + 1} failed: ${err.message} - skipping`);
    }
  }

  return geoMap;
}

async function main() {
  console.log('Fetching Feodo Tracker blocklist...');
  const raw = await get(FEODO_URL);

  // Feodo Tracker returns a plain JSON array (not wrapped in an object)
  const blocklist = Array.isArray(raw) ? raw : (raw.blocklist || []);
  console.log(`Got ${blocklist.length} entries`);

  // Extract unique IPs for geolocation
  const uniqueIps = [...new Set(blocklist.map(e => e.ip_address))];
  console.log(`Geolocating ${uniqueIps.length} unique IPs...`);

  const geoMap = await geolocate(uniqueIps);
  console.log(`Geolocation complete: ${Object.keys(geoMap).length}/${uniqueIps.length} resolved`);

  // Merge blocklist with geo data, add small jitter to prevent exact overlap
  const servers = blocklist.map(entry => {
    const geo  = geoMap[entry.ip_address] || {};
    const lat  = geo.lat != null ? geo.lat + (Math.random() - 0.5) * 0.4 : null;
    const lng  = geo.lng != null ? geo.lng + (Math.random() - 0.5) * 0.4 : null;

    return {
      ip:          entry.ip_address,
      port:        entry.port        || null,
      status:      entry.status      || 'offline',
      malware:     entry.malware     || 'Unknown',
      country:     geo.country       || entry.country || null,
      as_name:     geo.isp           || entry.as_name || null,
      first_seen:  entry.first_seen  || null,
      last_online: entry.last_online || null,
      lat,
      lng,
    };
  });

  const onlineCount = servers.filter(s => s.status === 'online').length;

  const output = {
    fetched_at:   new Date().toISOString(),
    count:        servers.length,
    online_count: onlineCount,
    servers,
  };

  fs.mkdirSync(path.dirname(OUT_FILE), { recursive: true });
  fs.writeFileSync(OUT_FILE, JSON.stringify(output));

  console.log(`Done. ${servers.length} servers (${onlineCount} online) written to data/live.json`);
}

main().catch(err => {
  console.error(err.message);
  process.exit(1);
});
