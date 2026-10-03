# Brand assets

Original artwork for scanward, covered by the project license. No third-party
logos or trademarks are used or referenced.

## Vector (source of truth)

| File | Use |
|---|---|
| `logo.svg` | Primary lockup on a dark plate. README headers, docs, slides — legible on light *and* dark pages. |
| `logo-light.svg` | Same lockup without the plate, dark ink. White docs pages, print. |
| `icon.svg` | Square mark on a dark tile. Repo avatar, app icon, favicon, docs headers. |
| `icon-flat.svg` | Single-colour silhouette, no gradients. Stamps, watermarks, engraving. |
| `social-preview.svg` | 1200×630 link-preview card source. |

## Raster (generated, checked in for consumers that need PNG)

| File | Size | Use |
|---|---|---|
| `icon-256.png` | 256×256 | avatars, small UI |
| `icon-512.png` | 512×512 | app icons, high-DPI favicons |
| `icon-flat.png` | 512×512 | one-tone contexts |
| `logo.png` | 660×144 | README/docs where SVG is unsupported |
| `logo-light.png` | 660×144 | as above, light background |
| `social-preview.png` | 1200×630 | link previews (upload in repo Settings) |

SVGs are the source of truth; regenerate the PNGs from them if the mark changes.
The icon PNGs have transparent corners — do not flatten them onto white.

## Concept

**scanward = *scan* + *ward*.** The mark is a shield — the *ward* half, static
analysis as protection — holding a single chevron: the *scan* half, and also a
code construct. The chevron is deliberately alone inside the shield: an earlier
iteration used a terminal prompt and then a four-corner viewfinder, and both
collapsed into an unreadable blob at favicon size. One bold element inside one
outline is the only thing that survives 16px. The wordmark is monospace because
the CLI is where the scan actually happens.

## Palette

| Token | Hex | Use |
|---|---|---|
| Ink | `#0A0F1A` / `#16203A` | plate, dark text, flat-variant strokes |
| Paper | `#F2F5FA` | wordmark and chevron on dark |
| Rust light | `#FF8A3D` | gradient start, `ward` accent on dark |
| Rust deep | `#E4572E` | gradient end, flat-variant accent, `ward` on light |

## Usage rules

- Clear space of at least the chevron's height around any asset.
- Do not recolour the gradient endpoints, stretch the lockup, swap the
  wordmark to a proportional face, or add a second inner element to the mark.
- Dark background → `logo.svg` (it carries its own plate). Light background →
  either `logo.svg` or `logo-light.svg`.
- At 16–32px use `icon.svg` or `icon-flat.png`; the lockup is not legible there.