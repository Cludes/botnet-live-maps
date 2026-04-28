// =============================================================
//  Botnet Live Maps - Configuration
// =============================================================

const CONFIG = {
  // ---- Data files (written by GitHub Actions, served by GitHub Pages) ----
  LIVE_DATA_URL: 'data/live.json',

  // ---- Map ----
  MAP_CENTER: [20, 10],
  MAP_ZOOM:    3,
  MAP_MIN_ZOOM: 2,
  MAP_MAX_ZOOM: 18,

  TILE_URL: 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
  TILE_ATTRIBUTION:
    '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors ' +
    '&copy; <a href="https://carto.com/attributions">CARTO</a> | ' +
    'C2 data &copy; <a href="https://feodotracker.abuse.ch/">Feodo Tracker / abuse.ch</a>',

  // ---- Refresh ----
  LIVE_REFRESH_MS: 300000, // 5 min - GH Actions updates every 6h, but poll for quick pickup

  // ---- Dot size ----
  DOT_SIZE: 10,

  // ---- Malware families and their colors ----
  MALWARE: {
    'Emotet':        { color: '#ff4444', label: 'Emotet' },
    'QakBot':        { color: '#ff8c00', label: 'QakBot' },
    'Qakbot':        { color: '#ff8c00', label: 'QakBot' },
    'Dridex':        { color: '#4488ff', label: 'Dridex' },
    'TrickBot':      { color: '#bb44ff', label: 'TrickBot' },
    'BazarLoader':   { color: '#00cccc', label: 'BazarLoader' },
    'IcedID':        { color: '#ffcc00', label: 'IcedID' },
    'CobaltStrike':  { color: '#ff0066', label: 'Cobalt Strike' },
    'Cobalt Strike': { color: '#ff0066', label: 'Cobalt Strike' },
    'AsyncRAT':      { color: '#00ff88', label: 'AsyncRAT' },
    'Pikabot':       { color: '#ff66aa', label: 'Pikabot' },
    'SmokeLoader':   { color: '#aaaaaa', label: 'SmokeLoader' },
  },

  DEFAULT_COLOR: '#888888',
};
