# Botnet Live Maps

A live world map of botnet command-and-control (C2) servers, plotted from the public [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/) threat feed. An educational, defensive visualization of where active malware C2 infrastructure is hosted.

**Live demo:** https://cludes.github.io/botnet-live-maps/

## Features

- World map of currently tracked C2 servers
- Data sourced from the abuse.ch Feodo Tracker public feed (Dridex, Emotet, TrickBot, QakBot, and similar families)
- Per-server detail: IP, malware family, hosting country, and status
- Fully static - runs entirely in the browser

## Structure

- `index.html`, `script.js`, `styles.css` - the app
- `config.js` - feed/configuration settings
- `data/` - fetched feed data

## Running locally

```bash
npx serve .
```

This project only consumes a public, read-only threat-intelligence feed for visualization. It does not control or interact with any botnet.
