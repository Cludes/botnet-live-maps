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

    this.showOnline  = true;
    this.showOffline = true;
    this.activeFamilies = new Set();

    this.panelOpen   = false;
    this._lastFetchedAt = undefined;
    this._pollTimer  = null;

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
      zoomControl: true,
    });

    this._tileLayer = L.tileLayer(this._tileUrl(), {
      attribution: CONFIG.TILE_ATTRIBUTION,
      subdomains:  'abcd',
      maxZoom:     20,
    }).addTo(this.map);

    this.dotGroup = L.layerGroup().addTo(this.map);
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
      this.setStatus('ok');

    } catch (err) {
      console.error('[Botnet] Fetch failed:', err.message);
      this.setStatus('error');
    }
  }

  // ---- Render all C2 dots ----
  renderDots() {
    // Clear existing markers
    this.dotGroup.clearLayers();
    this.dotMarkers.clear();

    for (const server of this.servers) {
      if (!server.lat || !server.lng) continue;
      if (!this.isVisible(server)) continue;
      this.addDot(server);
    }
  }

  isVisible(server) {
    const statusOk = (server.status === 'online' && this.showOnline)
                  || (server.status !== 'online' && this.showOffline);
    const familyOk = this.activeFamilies.has(server.malware);
    if (!statusOk || !familyOk) return false;
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

    const el = document.createElement('div');
    el.className = `c2dot${isOnline ? ' online' : ''}`;
    // Set CSS custom property for pulse color so each family pulses in its own color
    el.style.cssText = `background:${color};border-color:rgba(255,255,255,0.4);--pulse-color:${color}80;`;

    const icon = L.divIcon({
      html:       el,
      className:  '',
      iconSize:   [CONFIG.DOT_SIZE, CONFIG.DOT_SIZE],
      iconAnchor: [CONFIG.DOT_SIZE / 2, CONFIG.DOT_SIZE / 2],
    });

    const marker = L.marker([server.lat, server.lng], { icon, zIndexOffset: isOnline ? 200 : 0 });
    marker.on('click', () => this.showServerInfo(server));

    this.dotGroup.addLayer(marker);
    this.dotMarkers.set(server.ip, { marker, el });
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

    const ipStr = server.ip + (server.port ? ':' + server.port : '');
    document.getElementById('server-info-body').innerHTML = `
      <div class="si-family" style="color:${color}">${this.labelFor(server.malware)}</div>
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
    onlineItem.innerHTML = `<i class="ldot" style="background:#fff;opacity:0.7;animation:c2pulse 2.2s ease-out infinite"></i>Online (pulsing)`;
    container.appendChild(onlineItem);
  }

  // ---- Filters ----
  setFilter(type, enabled) {
    if (type === 'online')  this.showOnline  = enabled;
    if (type === 'offline') this.showOffline = enabled;
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

  // ---- Search ----
  _onSearch(term) {
    this._searchTerm = term.toLowerCase().trim();
    this.renderDots();
    this.updateCount();
  }
}
