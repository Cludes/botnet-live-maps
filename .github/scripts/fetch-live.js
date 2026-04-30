#!/usr/bin/env node
// =============================================================
//  fetch-live.js
//  Fetches data from three sources and merges them:
//    - Feodo Tracker  (abuse.ch)    - confirmed banking trojan C2s
//    - C2IntelFeeds   (drb-ra)      - suspected C2 IP:port (30+90 day)
//    - URLhaus        (abuse.ch)    - live malware distribution servers
//  Geo-enriches via ip-api.com, writes data/live.json.
//  No API keys required.
// =============================================================

'use strict';

const https = require('https');
const http  = require('http');
const net   = require('net');
const fs    = require('fs');
const path  = require('path');

const FEODO_URL       = 'https://feodotracker.abuse.ch/downloads/ipblocklist.json';
const C2INTEL_30D_URL = 'https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPPortC2s-30day.csv';
const C2INTEL_90D_URL = 'https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPPortC2s-90day.csv';
const URLHAUS_URL     = 'https://urlhaus.abuse.ch/downloads/csv_online/';
const IPAPI_URL       = 'http://ip-api.com/batch?fields=status,lat,lon,country,countryCode,isp,query';
const OUT_FILE      = path.join(__dirname, '../../data/live.json');

const BATCH_SIZE  = 100;
const BATCH_DELAY = 1500;

// ---- HTTP helpers ----

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

function getText(url) {
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
      res.on('end', () => resolve(body));
    }).on('error', reject);
  });
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ---- TCP probing ----

function probePort(ip, port, timeoutMs = 3000) {
  return new Promise(resolve => {
    const socket = new net.Socket();
    let done = false;
    const finish = online => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(online);
    };
    socket.setTimeout(timeoutMs);
    socket.on('connect', () => finish(true));
    socket.on('timeout', () => finish(false));
    socket.on('error',   () => finish(false));
    socket.connect(port, ip);
  });
}

async function probeEntries(entries, concurrency = 50, timeoutMs = 3000) {
  const results = new Map();
  const toProbe = entries.filter(e => e.port);
  for (let i = 0; i < toProbe.length; i += concurrency) {
    const batch = toProbe.slice(i, i + concurrency);
    const batchResults = await Promise.all(
      batch.map(e => probePort(e.ip, e.port, timeoutMs).then(online => ({ key: e.key, online })))
    );
    for (const { key, online } of batchResults) results.set(key, online);
    process.stdout.write(`  Probed ${Math.min(i + concurrency, toProbe.length)}/${toProbe.length}\r`);
  }
  console.log(`  Probe complete: ${toProbe.length} endpoints checked`);
  return results;
}

function chunks(arr, size) {
  const out = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

// ---- Geolocation ----

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
      console.log(`  Geo batch ${i + 1}/${batches.length}: ${results.filter(r => r.status === 'success').length} ok`);
    } catch (err) {
      console.warn(`  Geo batch ${i + 1} failed: ${err.message}`);
    }
  }
  return geoMap;
}

// ---- Source fetchers ----

async function fetchFeodo() {
  console.log('Fetching Feodo Tracker...');
  try {
    const raw       = await get(FEODO_URL);
    const blocklist = Array.isArray(raw) ? raw : (raw.blocklist || []);
    console.log(`  ${blocklist.length} entries`);
    return blocklist.map(e => ({
      key:         `${e.ip_address}:${e.port || 0}`,
      ip:          e.ip_address,
      port:        e.port        || null,
      status:      e.status      || 'offline',
      malware:     e.malware     || 'Unknown',
      first_seen:  e.first_seen  || null,
      last_online: e.last_online || null,
      source:      'feodo',
    }));
  } catch (err) {
    console.error(`  Feodo failed: ${err.message}`);
    return [];
  }
}

async function fetchC2IntelFeeds() {
  console.log('Fetching C2IntelFeeds (30-day + 90-day IP:port)...');
  try {
    const [text30, text90] = await Promise.all([getText(C2INTEL_30D_URL), getText(C2INTEL_90D_URL)]);

    const parseLines = text => text.split('\n')
      .filter(l => l.trim() && !l.startsWith('#'))
      .map(line => {
        const parts = line.split(',');
        const ip    = (parts[0] || '').trim();
        const port  = parseInt((parts[1] || '').trim(), 10) || null;
        const ioc   = (parts.slice(2).join(',') || '').trim();
        if (!ip) return null;
        let malware = ioc.replace(/^Possible\s+/i, '').replace(/\s+C2\s+(IP|Domain).*$/i, '').trim();
        if (/cobalt.?strike/i.test(malware)) malware = 'Cobalt Strike';
        return {
          key:         `${ip}:${port || 0}`,
          ip,
          port,
          status:      'offline',
          malware:     malware || 'Unknown',
          first_seen:  null,
          last_online: null,
          source:      'c2intel',
        };
      }).filter(Boolean);

    const entries30 = parseLines(text30);
    const entries90 = parseLines(text90);
    const seen = new Map();
    for (const e of [...entries30, ...entries90]) {
      if (!seen.has(e.key)) seen.set(e.key, e);
    }
    const all = [...seen.values()];
    console.log(`  ${all.length} unique entries (30d:${entries30.length} 90d:${entries90.length})`);
    return all;
  } catch (err) {
    console.error(`  C2IntelFeeds failed: ${err.message}`);
    return [];
  }
}

async function fetchURLhaus() {
  console.log('Fetching URLhaus (live malware distribution, IP-only)...');
  try {
    const text = await getText(URLHAUS_URL);
    const lines = text.split('\n').filter(l => l.trim() && !l.startsWith('#'));

    // Simple CSV parser that handles quoted fields containing commas
    const parseCSVLine = line => {
      const fields = [];
      let field = '', inQuote = false;
      for (const ch of line) {
        if (ch === '"')            inQuote = !inQuote;
        else if (ch === ',' && !inQuote) { fields.push(field); field = ''; }
        else                       field += ch;
      }
      fields.push(field);
      return fields;
    };

    const seen = new Map();
    for (const line of lines) {
      const f = parseCSVLine(line);
      if (f.length < 7) continue;
      const [, dateadded, url, , last_online, , tags] = f;

      let hostname, port;
      try {
        const u = new URL(url);
        hostname = u.hostname;
        port     = u.port ? parseInt(u.port) : (u.protocol === 'https:' ? 443 : 80);
      } catch { continue; }

      // Skip domain-based URLs — IP only to avoid DNS resolution
      if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) continue;

      // Extract meaningful malware family: skip lowercase arch/format tags, keep named families
      const tagList = tags.split(',').map(t => t.trim()).filter(t => t && t !== 'None' && /[A-Z]/.test(t));
      const malware = tagList.length ? tagList[tagList.length - 1] : 'Malware Dropper';

      const key = `${hostname}:${port || 0}`;
      if (!seen.has(key)) {
        seen.set(key, {
          key,
          ip:          hostname,
          port:        port || null,
          status:      'online', // URLhaus csv_online already verified
          malware,
          first_seen:  dateadded  || null,
          last_online: last_online || null,
          source:      'urlhaus',
        });
      }
    }

    const results = [...seen.values()];
    console.log(`  ${results.length} unique IP entries`);
    return results;
  } catch (err) {
    console.error(`  URLhaus failed: ${err.message}`);
    return [];
  }
}

// ---- Main ----

async function main() {
  const [feodo, c2intel, urlhaus] = await Promise.all([
    fetchFeodo(),
    fetchC2IntelFeeds(),
    fetchURLhaus(),
  ]);

  // Deduplicate by ip:port key. Priority: Feodo > C2Intel > URLhaus.
  const seen = new Map();
  for (const entry of [...feodo, ...c2intel, ...urlhaus]) {
    if (!seen.has(entry.key)) seen.set(entry.key, entry);
  }
  const merged = [...seen.values()];
  console.log(`\nMerged: ${merged.length} unique entries (feodo:${feodo.length} c2intel:${c2intel.length} urlhaus:${urlhaus.length})`);

  const uniqueIps = [...new Set(merged.map(e => e.ip))];
  console.log(`Geolocating ${uniqueIps.length} unique IPs...`);
  const geoMap = await geolocate(uniqueIps);
  console.log(`Geolocation complete: ${Object.keys(geoMap).length}/${uniqueIps.length} resolved`);

  // Probe C2IntelFeeds entries only — Feodo and URLhaus already have verified status
  const c2intelEntries = merged.filter(e => e.source === 'c2intel');
  console.log(`\nProbing ${c2intelEntries.length} C2IntelFeeds endpoints for live status...`);
  const probeResults = await probeEntries(c2intelEntries);
  for (const entry of merged) {
    if (entry.source === 'c2intel' && probeResults.has(entry.key)) {
      entry.status = probeResults.get(entry.key) ? 'online' : 'offline';
    }
  }

  const servers = merged.map(entry => {
    const geo = geoMap[entry.ip] || {};
    const lat = geo.lat != null ? geo.lat + (Math.random() - 0.5) * 0.4 : null;
    const lng = geo.lng != null ? geo.lng + (Math.random() - 0.5) * 0.4 : null;
    return {
      ip:          entry.ip,
      port:        entry.port,
      status:      entry.status,
      malware:     entry.malware,
      source:      entry.source,
      country:     geo.country    || null,
      as_name:     geo.isp        || null,
      first_seen:  entry.first_seen,
      last_online: entry.last_online,
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
  console.log(`\nDone. ${servers.length} servers (${onlineCount} online) written to data/live.json`);
}

main().catch(err => {
  console.error(err.message);
  process.exit(1);
});
