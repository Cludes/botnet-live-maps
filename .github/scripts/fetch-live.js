#!/usr/bin/env node
// =============================================================
//  fetch-live.js
//  Fetches C2 data from three sources and merges them:
//    - Feodo Tracker (abuse.ch) - banking trojans / loaders
//    - ThreatFox    (abuse.ch) - broad malware IOC database
//    - SSLBL        (abuse.ch) - SSL-based C2 blocklist
//  Geo-enriches via ip-api.com, writes data/live.json.
//  No API keys required.
// =============================================================

'use strict';

const https = require('https');
const http  = require('http');
const fs    = require('fs');
const path  = require('path');

const FEODO_URL     = 'https://feodotracker.abuse.ch/downloads/ipblocklist.json';
const SSLBL_URL     = 'https://sslbl.abuse.ch/blacklist/sslipbl.json';
const THREATFOX_URL = 'https://threatfox-api.abuse.ch/api/v1/';
const IPAPI_URL     = 'http://ip-api.com/batch?fields=status,lat,lon,country,countryCode,isp,query';
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

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

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

async function fetchSSLBL() {
  console.log('Fetching SSLBL...');
  try {
    const raw       = await get(SSLBL_URL);
    const blocklist = raw.blacklist || [];
    console.log(`  ${blocklist.length} entries`);
    return blocklist.map(e => {
      const malware = (e.Reason || 'Unknown').replace(/\s+C&C$/i, '').trim();
      return {
        key:         `${e.DstIP}:${e.DstPort || 0}`,
        ip:          e.DstIP,
        port:        e.DstPort ? parseInt(e.DstPort, 10) : null,
        status:      'offline',
        malware,
        first_seen:  e.first_seen  || null,
        last_online: null,
        source:      'sslbl',
      };
    });
  } catch (err) {
    console.error(`  SSLBL failed: ${err.message}`);
    return [];
  }
}

async function fetchThreatFox() {
  console.log('Fetching ThreatFox (last 14 days, ip:port IOCs)...');
  try {
    const raw = await post(THREATFOX_URL, { query: 'get_iocs', days: 14 });
    if (raw.query_status !== 'ok' || !Array.isArray(raw.data)) {
      console.log('  No data returned');
      return [];
    }
    const iocs = raw.data.filter(e => e.ioc_type === 'ip:port' && (e.confidence_level || 0) >= 50);
    console.log(`  ${iocs.length} ip:port IOCs (confidence >= 50, from ${raw.data.length} total)`);
    return iocs.map(e => {
      const lastColon = e.ioc.lastIndexOf(':');
      const ip   = e.ioc.slice(0, lastColon);
      const port = parseInt(e.ioc.slice(lastColon + 1), 10) || null;
      return {
        key:         `${ip}:${port || 0}`,
        ip,
        port,
        status:      'offline',
        malware:     e.malware_printable || e.malware || 'Unknown',
        first_seen:  e.first_seen  || null,
        last_online: e.last_seen   || null,
        source:      'threatfox',
      };
    });
  } catch (err) {
    console.error(`  ThreatFox failed: ${err.message}`);
    return [];
  }
}

// ---- Main ----

async function main() {
  const [feodo, sslbl, threatfox] = await Promise.all([
    fetchFeodo(),
    fetchSSLBL(),
    fetchThreatFox(),
  ]);

  // Deduplicate by ip:port key. Feodo takes priority (most curated),
  // then SSLBL, then ThreatFox.
  const seen = new Map();
  for (const entry of [...feodo, ...sslbl, ...threatfox]) {
    if (!seen.has(entry.key)) seen.set(entry.key, entry);
  }
  const merged = [...seen.values()];
  console.log(`\nMerged: ${merged.length} unique entries (feodo:${feodo.length} sslbl:${sslbl.length} threatfox:${threatfox.length})`);

  const uniqueIps = [...new Set(merged.map(e => e.ip))];
  console.log(`Geolocating ${uniqueIps.length} unique IPs...`);
  const geoMap = await geolocate(uniqueIps);
  console.log(`Geolocation complete: ${Object.keys(geoMap).length}/${uniqueIps.length} resolved`);

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
