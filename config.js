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
    urlhaus: 'URLhaus',
  },

  // ---- Malware families and their colors ----
  MALWARE: {
    // Feodo Tracker (banking trojans / loaders) - warm reds/oranges so they pop
    'Emotet':          { color: '#ff3300', label: 'Emotet' },
    'QakBot':          { color: '#ffaa00', label: 'QakBot' },
    'Qakbot':          { color: '#ffaa00', label: 'QakBot' },
    'Dridex':          { color: '#ff6600', label: 'Dridex' },
    'TrickBot':        { color: '#ff8800', label: 'TrickBot' },
    'BazarLoader':     { color: '#ffcc00', label: 'BazarLoader' },
    'IcedID':          { color: '#ffee44', label: 'IcedID' },
    'Pikabot':         { color: '#ffdd88', label: 'Pikabot' },
    'SmokeLoader':     { color: '#cc9900', label: 'SmokeLoader' },
    // C2 frameworks - cyan/teal family (dominant in C2IntelFeeds)
    'CobaltStrike':    { color: '#00ccff', label: 'Cobalt Strike' },
    'Cobalt Strike':   { color: '#00ccff', label: 'Cobalt Strike' },
    'Metasploit':      { color: '#00ffcc', label: 'Metasploit' },
    'Sliver':          { color: '#44ffee', label: 'Sliver' },
    'Havoc':           { color: '#00eeff', label: 'Havoc' },
    // RATs - purple/violet
    'AsyncRAT':        { color: '#cc44ff', label: 'AsyncRAT' },
    'njRAT':           { color: '#aa33ff', label: 'njRAT' },
    'NjRAT':           { color: '#aa33ff', label: 'njRAT' },
    'Remcos':          { color: '#dd55ff', label: 'Remcos' },
    'DCRat':           { color: '#bb44ee', label: 'DCRat' },
    'XWorm':           { color: '#ee66ff', label: 'XWorm' },
    'QuasarRAT':       { color: '#9933ff', label: 'QuasarRAT' },
    'Quasar RAT':      { color: '#9933ff', label: 'QuasarRAT' },
    // Stealers - green
    'RedLine':         { color: '#00ff88', label: 'RedLine' },
    'RedLine Stealer': { color: '#00ff88', label: 'RedLine' },
    'AgentTesla':      { color: '#44ee88', label: 'AgentTesla' },
    'Agent Tesla':     { color: '#44ee88', label: 'AgentTesla' },
    'LummaC2':         { color: '#00ee66', label: 'LummaC2' },
    'Lumma':           { color: '#00ee66', label: 'LummaC2' },
    'Vidar':           { color: '#33ff99', label: 'Vidar' },
    'Amadey':          { color: '#55dd77', label: 'Amadey' },
    // Other
    'PlugX':           { color: '#ff5588', label: 'PlugX' },
    'MedusaLocker':    { color: '#ff4477', label: 'MedusaLocker' },
    'LockBit':         { color: '#ff2255', label: 'LockBit' },
    'REvil':           { color: '#dd1144', label: 'REvil' },
    'BlackMatter':     { color: '#cc0033', label: 'BlackMatter' },
    // URLhaus malware droppers
    'Mozi':            { color: '#00ff44', label: 'Mozi' },
    'Mirai':           { color: '#44ff88', label: 'Mirai' },
    'Gafgyt':          { color: '#88ffaa', label: 'Gafgyt' },
    'ClearFake':       { color: '#ffee55', label: 'ClearFake' },
    'Malware Dropper': { color: '#aaaaaa', label: 'Malware Dropper' },
  },

  DEFAULT_COLOR: '#888888',

  // ---- Threat level weights (per online server of that family) ----
  THREAT_WEIGHTS: {
    'Emotet':        50,
    'QakBot':        40, 'Qakbot':      40,
    'TrickBot':      40,
    'BazarLoader':   35,
    'IcedID':        35,
    'Dridex':        30,
    'Pikabot':       30,
    'LockBit':       45,
    'REvil':         45,
    'BlackMatter':   40,
    'SmokeLoader':   25,
    'Cobalt Strike': 20, 'CobaltStrike': 20,
    'Havoc':         20,
    'LummaC2':       20, 'Lumma':        20,
    'Metasploit':    15,
    'Sliver':        15,
    'RedLine':       15, 'RedLine Stealer': 15,
    'AsyncRAT':      10,
    'njRAT':         10, 'NjRAT':         10,
  },
};
