/* ============================================================
   BotnetLiveMap - Main Application

   Data flow:
     data/live.json  - C2 server list fetched every 6h by GH Actions
                       from Feodo Tracker (abuse.ch), geo-enriched via
                       ip-api.com. Browser never calls external APIs directly.
   ============================================================ */

'use strict';

class BotnetLiveMap {
  constructor() {
    this.map         = null;
    this.dotGroup    = null;
    this.dotMarkers  = new Map(); // ip -> { marker, el }

    this.servers     = [];        // full list from live.json
    this.families    = new Set(); // unique malware families seen

    this.showOnline   = true;
    this.showOffline  = true;
    this.showFeodo    = true;
    this.showC2Intel  = true;
    this.activeFamilies = new Set();

    this.panelOpen   = false;
    this._lastFetchedAt = undefined;
    this._pollTimer  = null;
    this._viewMode   = 'heat';
    this._heatLayer  = null;

    this._theme      = 'dark';
    this._searchTerm = '';
    this._tileLayer  = null;
  }

  // ---- Entry point ----
  async init() {
    this._loadTheme();
    this.initMap();
    this.setupKeyboard();
    await this.fetchLiveData();
    this.startPolling();
  }

  // ---- Map setup ----
  initMap() {
    this.map = L.map('map', {
      center:   CONFIG.MAP_CENTER,
      zoom:     CONFIG.MAP_ZOOM,
      minZoom:  CONFIG.MAP_MIN_ZOOM,
      maxZoom:  CONFIG.MAP_MAX_ZOOM,
      zoomControl:        true,
      worldCopyJump:      false,
      maxBounds:          [[-85, -180], [85, 180]],
      maxBoundsViscosity: 1.0,
    });

    this._tileLayer = L.tileLayer(this._tileUrl(), {
      attribution: CONFIG.TILE_ATTRIBUTION,
      subdomains:  'abcd',
      maxZoom:     20,
      noWrap:      true,
    }).addTo(this.map);

    this._renderer = L.canvas({ padding: 0.5 });
    this.dotGroup  = L.layerGroup();
  }

  // ---- Fetch live.json ----
  async fetchLiveData() {
    this.setStatus('loading');

    try {
      const res  = await fetch(`${CONFIG.LIVE_DATA_URL}?t=${Date.now()}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();

      if (data.fetched_at === this._lastFetchedAt) {
        this.setStatus('ok');
        return;
      }
      this._lastFetchedAt = data.fetched_at;

      this.servers = data.servers || [];

      if (!data.fetched_at) {
        this.setSetupOverlay(true);
        this.setCount('Waiting for first fetch...');
        this.setStatus('ok');
        return;
      }

      this.setSetupOverlay(false);

      // Collect families for filter UI
      const seenFamilies = new Set(this.servers.map(s => s.malware).filter(Boolean));
      const familiesChanged = [...seenFamilies].some(f => !this.families.has(f))
                           || [...this.families].some(f => !seenFamilies.has(f));
      this.families = seenFamilies;
      this.activeFamilies = new Set(seenFamilies);

      if (familiesChanged) {
        this.buildFamilyFilters();
        this.buildLegend();
      }

      this.renderDots();
      this.updateCount();
      this.setLastUpdate(new Date(data.fetched_at));
      this._checkStale(data.fetched_at);
      this._buildCountryBreakdown();
      this._buildHostingBreakdown();
      this._buildPortBreakdown();
      this.setStatus('ok');

    } catch (err) {
      console.error('[Botnet] Fetch failed:', err.message);
      this.setStatus('error');
    }
  }

  // ---- Render all C2 dots ----
  renderDots() {
    this.dotGroup.clearLayers();
    this.dotMarkers.clear();

    const visible = this.servers.filter(s => s.lat && s.lng && this.isVisible(s));

    if (this._viewMode === 'heat') {
      if (this.map.hasLayer(this.dotGroup)) this.map.removeLayer(this.dotGroup);
      this._buildHeatmap(visible);
      return;
    }

    if (this._heatLayer) { this._heatLayer.remove(); this._heatLayer = null; }
    for (const server of visible) this.addDot(server);
  }

  // ---- View mode (dots / heatmap) ----
  setViewMode(mode) {
    this._viewMode = mode;
    if (mode === 'heat') {
      this.map.removeLayer(this.dotGroup);
    } else {
      if (this._heatLayer) { this._heatLayer.remove(); this._heatLayer = null; }
      this.dotGroup.addTo(this.map);
    }
    this.renderDots();
  }

  _buildHeatmap(visibleServers) {
    if (this._heatLayer) { this._heatLayer.remove(); this._heatLayer = null; }
    const points = visibleServers.map(s => [s.lat, s.lng, s.status === 'online' ? 1.0 : 0.3]);
    this._heatLayer = L.heatLayer(points, {
      radius:   28,
      blur:     18,
      maxZoom:  10,
      gradient: {
        0.0:  'rgba(0,0,0,0)',
        0.25: '#00005a',
        0.4:  '#0033cc',
        0.55: '#00aaff',
        0.7:  '#00ffcc',
        0.82: '#ffdd00',
        0.92: '#ff6600',
        1.0:  '#ffffff',
      },
    }).addTo(this.map);
  }

  isVisible(server) {
    const statusOk = (server.status === 'online' && this.showOnline)
                  || (server.status !== 'online' && this.showOffline);
    const src      = server.source || 'feodo';
    const sourceOk = (src === 'feodo'   && this.showFeodo)
                  || (src === 'c2intel' && this.showC2Intel);
    const familyOk = this.activeFamilies.has(server.malware);
    if (!statusOk || !sourceOk || !familyOk) return false;
    if (this._searchTerm) {
      const t = this._searchTerm;
      return (server.ip && server.ip.includes(t))
          || (server.country && server.country.toLowerCase().includes(t));
    }
    return true;
  }

  addDot(server) {
    const color    = this.colorFor(server.malware);
    const isOnline = server.status === 'online';

    const marker = L.circleMarker([server.lat, server.lng], {
      renderer:    this._renderer,
      radius:      isOnline ? 6 : 3.5,
      fillColor:   color,
      fillOpacity: isOnline ? 1.0 : 0.55,
      color:       isOnline ? 'rgba(255,255,255,0.85)' : 'rgba(255,255,255,0.12)',
      weight:      isOnline ? 2 : 0.5,
    });

    marker.on('click', () => this.showServerInfo(server));
    this.dotGroup.addLayer(marker);
    this.dotMarkers.set(server.ip, { marker });
  }

  colorFor(malware) {
    const cfg = CONFIG.MALWARE[malware];
    return cfg ? cfg.color : CONFIG.DEFAULT_COLOR;
  }

  labelFor(malware) {
    const cfg = CONFIG.MALWARE[malware];
    return cfg ? cfg.label : (malware || 'Unknown');
  }

  // ---- Server detail popup ----
  showServerInfo(server) {
    const color    = this.colorFor(server.malware);
    const isOnline = server.status === 'online';

    const ipStr    = server.ip + (server.port ? ':' + server.port : '');
    const srcKey   = server.source || 'feodo';
    const srcLabel = CONFIG.SOURCE_LABELS[srcKey] || 'Feodo Tracker';
    document.getElementById('server-info-body').innerHTML = `
      <div class="si-top">
        <div class="si-family" style="color:${color}">${this.labelFor(server.malware)}</div>
        <span class="si-src-badge si-src-${srcKey}">${srcLabel}</span>
      </div>
      <div class="si-ip-row">
        <span class="si-ip">${ipStr}</span>
        <button class="si-copy-btn" onclick="app.copyIP('${ipStr}')" title="Copy to clipboard">
          <svg viewBox="0 0 16 16" width="13" height="13" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><rect x="4" y="4" width="9" height="10" rx="1.5"/><path d="M3 11H2a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1h8a1 1 0 0 1 1 1v1"/></svg>
        </button>
      </div>
      <div class="si-row">
        <span class="si-label">Status</span>
        <span class="si-value ${isOnline ? 'si-online' : 'si-offline'}">${isOnline ? 'Online' : 'Offline'}</span>
      </div>
      <div class="si-row">
        <span class="si-label">Country</span>
        <span class="si-value">${server.country || '-'}</span>
      </div>
      ${server.as_name ? `
      <div class="si-row">
        <span class="si-label">Host</span>
        <span class="si-value" style="max-width:170px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${server.as_name}">${server.as_name}</span>
      </div>` : ''}
      ${server.first_seen ? `
      <div class="si-row">
        <span class="si-label">First seen</span>
        <span class="si-value">${server.first_seen.slice(0, 10)}</span>
      </div>` : ''}
      ${server.last_online ? `
      <div class="si-row">
        <span class="si-label">Last online</span>
        <span class="si-value">${server.last_online}</span>
      </div>` : ''}
    `;

    document.getElementById('server-info').classList.remove('hidden');
  }

  closeServerInfo() {
    document.getElementById('server-info').classList.add('hidden');
  }

  // ---- Family filter chips ----
  buildFamilyFilters() {
    const container = document.getElementById('family-filters');
    if (!container) return;
    container.innerHTML = `
      <div class="filter-actions">
        <button class="filter-all-btn" onclick="app.setAllFamilies(true)">All</button>
        <button class="filter-all-btn" onclick="app.setAllFamilies(false)">None</button>
      </div>`;

    const counts = {};
    for (const s of this.servers) {
      counts[s.malware] = (counts[s.malware] || 0) + 1;
    }

    const sorted = [...this.families].sort((a, b) => (counts[b] || 0) - (counts[a] || 0));

    for (const family of sorted) {
      const color = this.colorFor(family);
      const label = this.labelFor(family);
      const count = counts[family] || 0;

      const el = document.createElement('div');
      el.className = 'ff-item';
      el.dataset.family = family;
      el.innerHTML =
        `<span class="ff-dot" style="background:${color}"></span>` +
        `<span>${label}</span>` +
        `<span class="ff-count">${count}</span>`;

      el.addEventListener('click', () => {
        if (this.activeFamilies.has(family)) {
          this.activeFamilies.delete(family);
          el.classList.add('off');
        } else {
          this.activeFamilies.add(family);
          el.classList.remove('off');
        }
        this.renderDots();
        this.updateCount();
      });

      container.appendChild(el);
    }
  }

  // ---- Legend ----
  buildLegend() {
    const container = document.getElementById('legend-items');
    if (!container) return;
    container.innerHTML = '';

    const seen = new Set();
    for (const family of this.families) {
      const label = this.labelFor(family);
      if (seen.has(label)) continue;
      seen.add(label);

      const color = this.colorFor(family);
      const item = document.createElement('div');
      item.className = 'legend-item';
      item.innerHTML = `<i class="ldot" style="background:${color}"></i>${label}`;
      container.appendChild(item);
    }

    // Always show online/offline distinction
    const onlineItem = document.createElement('div');
    onlineItem.className = 'legend-item';
    onlineItem.style.marginTop = '8px';
    onlineItem.innerHTML = `<i class="ldot" style="background:#fff;opacity:0.85;box-shadow:0 0 4px #fff"></i>Online (large/bright)`;
    container.appendChild(onlineItem);
  }

  // ---- Filters ----
  setFilter(type, enabled) {
    if (type === 'online')   this.showOnline  = enabled;
    if (type === 'offline')  this.showOffline = enabled;
    if (type === 'feodo')    this.showFeodo   = enabled;
    if (type === 'c2intel')  this.showC2Intel = enabled;
    this.renderDots();
    this.updateCount();
  }

  // ---- Panel ----
  togglePanel() {
    this.panelOpen = !this.panelOpen;
    const panel  = document.getElementById('panel');
    const legend = document.getElementById('legend');
    panel.classList.toggle('panel-hidden', !this.panelOpen);
    panel.setAttribute('aria-hidden', String(!this.panelOpen));
    if (legend) legend.style.right = this.panelOpen ? 'calc(var(--panel-w) + 14px)' : '14px';
  }

  // ---- Keyboard ----
  setupKeyboard() {
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape') this.closeServerInfo();
      if (e.target.tagName === 'INPUT') return;
      if (e.key === 'f' && !e.ctrlKey && !e.metaKey) this.toggleFullscreen();
      if (e.key === 'p' && !e.ctrlKey && !e.metaKey) this.togglePanel();
    });
  }

  // ---- Actions ----
  resetView()        { this.map.setView(CONFIG.MAP_CENTER, CONFIG.MAP_ZOOM); }
  toggleFullscreen() {
    if (!document.fullscreenElement) document.documentElement.requestFullscreen().catch(() => {});
    else document.exitFullscreen().catch(() => {});
  }

  // ---- Polling ----
  startPolling() {
    this._pollTimer = setInterval(() => this.fetchLiveData(), CONFIG.LIVE_REFRESH_MS);
  }

  // ---- Status helpers ----
  setStatus(state) {
    const el = document.getElementById('api-dot');
    if (!el) return;
    el.className = { ok: 'dot-ok', error: 'dot-error', loading: 'dot-loading' }[state] || 'dot-loading';
    el.title     = { ok: 'Live',   error: 'Data error', loading: 'Updating...' }[state] || '';
  }

  updateCount() {
    const visible = this.servers.filter(s => this.isVisible(s)).length;
    const online  = this.servers.filter(s => s.status === 'online' && this.isVisible(s)).length;
    this.setCount(`${visible} C2 servers (${online} online)`);
  }

  setCount(text) {
    const el = document.getElementById('server-count');
    if (el) el.textContent = text;
  }

  setLastUpdate(date) {
    const el = document.getElementById('last-update');
    if (el) el.textContent = `Updated: ${date.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}`;
  }

  setSetupOverlay(visible) {
    const el = document.getElementById('setup-overlay');
    if (el) el.classList.toggle('hidden', !visible);
  }

  // ---- Theme ----
  _loadTheme() {
    this._theme = localStorage.getItem('botnet-theme') || 'dark';
    document.documentElement.setAttribute('data-theme', this._theme);
  }

  _tileUrl() {
    return this._theme === 'light' ? CONFIG.TILE_URL_LIGHT : CONFIG.TILE_URL;
  }

  toggleTheme() {
    this._theme = this._theme === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', this._theme);
    localStorage.setItem('botnet-theme', this._theme);
    if (this._tileLayer) this._tileLayer.setUrl(this._tileUrl());
  }

  // ---- Stale data warning ----
  _checkStale(fetchedAt) {
    const el = document.getElementById('stale-warning');
    if (!el || !fetchedAt) return;
    const ageH = (Date.now() - new Date(fetchedAt).getTime()) / 3600000;
    el.classList.toggle('hidden', ageH < 12);
  }

  // ---- Copy IP ----
  copyIP(ipStr) {
    navigator.clipboard.writeText(ipStr).then(() => {
      const btn = document.querySelector('.si-copy-btn');
      if (!btn) return;
      btn.classList.add('copied');
      setTimeout(() => btn.classList.remove('copied'), 1500);
    }).catch(() => {});
  }

  // ---- All / None families ----
  setAllFamilies(visible) {
    if (visible) {
      this.activeFamilies = new Set(this.families);
    } else {
      this.activeFamilies.clear();
    }
    document.querySelectorAll('.ff-item').forEach(el => {
      el.classList.toggle('off', !visible);
    });
    this.renderDots();
    this.updateCount();
  }

  // ---- Country breakdown ----
  _buildCountryBreakdown() {
    const container = document.getElementById('country-list');
    if (!container) return;
    const counts = {};
    for (const s of this.servers) {
      const c = s.country || 'Unknown';
      counts[c] = (counts[c] || 0) + 1;
    }
    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 12);
    const max    = sorted[0]?.[1] || 1;
    container.innerHTML = sorted.map(([country, count]) => `
      <div class="cl-item">
        <span class="cl-name">${country}</span>
        <div class="cl-bar-wrap">
          <div class="cl-bar" style="width:${Math.round(count / max * 100)}%"></div>
        </div>
        <span class="cl-count">${count}</span>
      </div>`).join('');
  }

  // ---- Hosting provider breakdown ----
  _buildHostingBreakdown() {
    const container = document.getElementById('hosting-list');
    if (!container) return;
    const NORM = [
      [/amazon|aws/i,          'Amazon AWS'],
      [/digitalocean/i,        'DigitalOcean'],
      [/microsoft|azure/i,     'Microsoft Azure'],
      [/google/i,              'Google Cloud'],
      [/cloudflare/i,          'Cloudflare'],
      [/hetzner/i,             'Hetzner'],
      [/ovh/i,                 'OVH'],
      [/vultr/i,               'Vultr'],
      [/linode|akamai/i,       'Linode/Akamai'],
      [/sakura/i,              'Sakura Internet'],
      [/alibaba|aliyun/i,      'Alibaba Cloud'],
      [/tencent/i,             'Tencent Cloud'],
    ];
    const counts = {};
    for (const s of this.servers) {
      if (!s.as_name) continue;
      let host = s.as_name;
      const match = NORM.find(([re]) => re.test(host));
      host = match ? match[1] : (host.length > 22 ? host.slice(0, 22) + '...' : host);
      counts[host] = (counts[host] || 0) + 1;
    }
    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8);
    const max    = sorted[0]?.[1] || 1;
    container.innerHTML = sorted.map(([host, count]) => `
      <div class="cl-item">
        <span class="cl-name">${host}</span>
        <div class="cl-bar-wrap">
          <div class="cl-bar" style="width:${Math.round(count / max * 100)}%"></div>
        </div>
        <span class="cl-count">${count}</span>
      </div>`).join('');
  }

  // ---- Port breakdown ----
  _buildPortBreakdown() {
    const container = document.getElementById('port-list');
    if (!container) return;
    const counts = {};
    for (const s of this.servers) {
      if (!s.port) continue;
      counts[s.port] = (counts[s.port] || 0) + 1;
    }
    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8);
    const max    = sorted[0]?.[1] || 1;
    container.innerHTML = sorted.map(([port, count]) => `
      <div class="cl-item">
        <span class="cl-name">:${port}</span>
        <div class="cl-bar-wrap">
          <div class="cl-bar" style="width:${Math.round(count / max * 100)}%"></div>
        </div>
        <span class="cl-count">${count}</span>
      </div>`).join('');
  }

  // ---- Search ----
  _onSearch(term) {
    this._searchTerm = term.toLowerCase().trim();
    this.renderDots();
    this.updateCount();
  }
}
