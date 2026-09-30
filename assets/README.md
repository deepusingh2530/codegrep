# Brand assets

Original artwork for codegrep, covered by the project license. No third-party logos or
trademarks are used or referenced; the mark is an original composition.

| File | Use |
|---|---|
| `logo.svg` | Primary lockup (mark + wordmark) on a dark plate. Use on README headers, docs, slides, social preview — legible on light *and* dark pages. |
| `logo-light.svg` | Same lockup without the plate, dark ink. Use when the background is already light (white docs pages, print). |
| `icon.svg` | Square mark on a dark tile. Use for the GitHub repo avatar, app icon, favicon, SARIF/tooling surfaces. |
| `icon-flat.svg` | Single-color silhouette (no gradients). Use for one-tone contexts: stamps, watermarks, engraving, tiny favicons. |

## Concept

The mark is a shield (the *SAST* half: static analysis, security posture)
containing a shell prompt `>_` (the *grep* half: pattern search over source,
a CLI-first tool). The wordmark is set in a monospace face because the CLI is
where the scan actually happens.

## Palette

| Token | Hex | Use |
|---|---|---|
| Ink | `#0A0F1A` / `#16203A` | Plate, dark text, shield strokes (flat variant) |
| Paper | `#F2F5FA` | Wordmark + prompt glyphs on dark |
| Rust light | `#FF8A3D` | "grep" accent, shield gradient start |
| Rust deep | `#E4572E` | Shield gradient end, flat-variant accent |

## Usage rules

- Keep clear space of at least the height of the shield's inner prompt around
  any asset.
- Do not recolor the gradient endpoints, stretch the lockup, or set the
  wordmark in a proportional face — the mono setting is intentional.
- For dark backgrounds use `logo.svg` (it carries its own plate); for light
  backgrounds either `logo.svg` or `logo-light.svg` works.
