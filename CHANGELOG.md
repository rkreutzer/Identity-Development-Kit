# Changelog

## Unreleased
- Fix: the npm packages (`@sphereon/idk-*`) could not be imported because they referenced Kotlin/JS runtime modules such as `../kotlin-kotlin-stdlib.mjs` that no package shipped. The runtime modules are now included in each package under `idk-runtime/` (#3).

## 0.25.0 — 2026-04-14
- First public release of the IDK
