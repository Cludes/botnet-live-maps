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

  TILE_URL:       'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
  TILE_URL_LIGHT: 'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png',
  TILE_ATTRIBUTION:
    '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors ' +
    '&copy; <a href="https://carto.com/attributions">CARTO</a> | ' +
    'C2 data &copy; <a href="https://feodotracker.abuse.ch/">Feodo Tracker / abuse.ch</a>',

  // ---- Refresh ----
  LIVE_REFRESH_MS: 300000, // 5 min - GH Actions updates every 6h, but poll for quick pickup

  // ---- Dot size ----
  DOT_SIZE: 10,

  // ---- Data source labels ----
  SOURCE_LABELS: {
    feodo:   'Feodo Tracker',
    c2intel: 'C2IntelFeeds',
  },

  // ---- Malware families and their colors ----
  MALWARE: {
    // Feodo Tracker families
    'Emotet':          { color: '#ff4444', label: 'Emotet' },
    'QakBot':          { color: '#ff8c00', label: 'QakBot' },
    'Qakbot':          { color: '#ff8c00', label: 'QakBot' },
    'Dridex':          { color: '#4488ff', label: 'Dridex' },
    'TrickBot':        { color: '#bb44ff', label: 'TrickBot' },
    'BazarLoader':     { color: '#00cccc', label: 'BazarLoader' },
    'IcedID':          { color: '#ffcc00', label: 'IcedID' },
    'CobaltStrike':    { color: '#ff0066', label: 'Cobalt Strike' },
    'Cobalt Strike':   { color: '#ff0066', label: 'Cobalt Strike' },
    'AsyncRAT':        { color: '#00ff88', label: 'AsyncRAT' },
    'Pikabot':         { color: '#ff66aa', label: 'Pikabot' },
    'SmokeLoader':     { color: '#aaaaaa', label: 'SmokeLoader' },
    // ThreatFox / SSLBL families
    'njRAT':           { color: '#44ee77', label: 'njRAT' },
    'NjRAT':           { color: '#44ee77', label: 'njRAT' },
    'RedLine':         { color: '#ff6633', label: 'RedLine' },
    'RedLine Stealer': { color: '#ff6633', label: 'RedLine' },
    'AgentTesla':      { color: '#aa44ff', label: 'AgentTesla' },
    'Agent Tesla':     { color: '#aa44ff', label: 'AgentTesla' },
    'Remcos':          { color: '#ff44bb', label: 'Remcos' },
    'DCRat':           { color: '#44aaff', label: 'DCRat' },
    'XWorm':           { color: '#ffcc44', label: 'XWorm' },
    'Metasploit':      { color: '#ff2255', label: 'Metasploit' },
    'Sliver':          { color: '#22ccff', label: 'Sliver' },
    'Havoc':           { color: '#ff8800', label: 'Havoc' },
    'LummaC2':         { color: '#ffdd00', label: 'LummaC2' },
    'Lumma':           { color: '#ffdd00', label: 'LummaC2' },
    'Vidar':           { color: '#ee44aa', label: 'Vidar' },
    'Amadey':          { color: '#66aaff', label: 'Amadey' },
    'PlugX':           { color: '#ff6600', label: 'PlugX' },
    'QuasarRAT':       { color: '#44ffcc', label: 'QuasarRAT' },
    'Quasar RAT':      { color: '#44ffcc', label: 'QuasarRAT' },
    'MedusaLocker':    { color: '#dd6688', label: 'MedusaLocker' },
    'BlackMatter':     { color: '#882244', label: 'BlackMatter' },
    'REvil':           { color: '#cc2222', label: 'REvil' },
    'LockBit':         { color: '#cc4400', label: 'LockBit' },
  },

  DEFAULT_COLOR: '#888888',
};
