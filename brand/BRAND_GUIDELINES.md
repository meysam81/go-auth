# go-auth Brand Guidelines

This document outlines the visual identity system for **go-auth**, a production-ready authentication library for Go applications.

---

## Brand Essence

| Attribute | Expression |
|-----------|------------|
| **Security** | Shield iconography, deep navy backgrounds, lock/key elements |
| **Trust** | Professional color palette, clean typography, enterprise-ready feel |
| **Go Ecosystem** | Go Cyan (#00ADD8) as primary color, monospace typography |
| **Modularity** | Geometric shapes, clean lines, building-block visual language |
| **Simplicity** | Minimal design, generous whitespace, focused messaging |

---

## Logo

### Primary Logo (Full)
**File:** `logo-full.svg`

The primary logo combines the shield mark with the wordmark. Use this version when space permits and brand recognition is important.

- Minimum width: 200px
- Clear space: Equal to the height of the shield on all sides

### Icon Logo
**File:** `logo-icon.svg`

The standalone shield mark for use in constrained spaces, app icons, or when the brand is already established in context.

- Minimum size: 32x32px
- Use when wordmark would be illegible

### Favicon
**File:** `favicon.svg`

Simplified shield optimized for small sizes (16x16, 32x32).

---

## Color Palette

### Primary Colors

| Name | Hex | RGB | Usage |
|------|-----|-----|-------|
| **Go Cyan** | `#00ADD8` | rgb(0, 173, 216) | Primary brand color, "go" in wordmark, CTAs |
| **Deep Navy** | `#0D2137` | rgb(13, 33, 55) | Backgrounds, "auth" in wordmark, depth |
| **Teal Accent** | `#14B8A6` | rgb(20, 184, 166) | Key icon, secondary actions, success states |

### Secondary Colors

| Name | Hex | RGB | Usage |
|------|-----|-----|-------|
| **Cyan Dark** | `#0891B2` | rgb(8, 145, 178) | Gradient endpoints, hover states |
| **Teal Dark** | `#0D9488` | rgb(13, 148, 136) | Gradient endpoints |
| **Slate** | `#64748B` | rgb(100, 116, 139) | Hyphen, secondary text |
| **Slate Light** | `#94A3B8` | rgb(148, 163, 184) | Body text on dark, captions |

### Neutral Colors

| Name | Hex | Usage |
|------|-----|-------|
| **White** | `#FFFFFF` | Text on dark, backgrounds |
| **Off-White** | `#F8FAFC` | Light backgrounds |
| **Charcoal** | `#1E293B` | Text on light |

### Color Ratios

- **Primary (Go Cyan):** 60% - Main brand presence
- **Secondary (Deep Navy):** 30% - Supporting depth
- **Accent (Teal):** 10% - Highlights and emphasis

---

## Typography

### Primary Typeface

**JetBrains Mono** (or fallbacks: SF Mono, Fira Code, Consolas, monospace)

Used for:
- Logo wordmark
- Code snippets
- Technical identifiers

### Secondary Typeface

**Inter** (or fallbacks: SF Pro Display, system-ui, sans-serif)

Used for:
- Body text
- Taglines
- UI elements
- Marketing copy

### Font Weights

| Weight | Usage |
|--------|-------|
| 700 (Bold) | Logo wordmark, headings |
| 600 (Semibold) | Subheadings, emphasis |
| 500 (Medium) | Taglines |
| 400 (Regular) | Body text |

---

## Iconography

### The Shield

The shield represents:
- **Protection** - Core purpose of authentication
- **Trust** - Enterprise-grade security
- **Stability** - Reliable, battle-tested code

### The Key

The key represents:
- **Access** - Controlled entry
- **Authentication** - Identity verification
- **Simplicity** - Straightforward API design

### Icon Style

- Geometric, clean lines
- 2-4px stroke weights
- Rounded corners (2-4px radius)
- Dual-tone: Primary action in Cyan, secondary in Teal

---

## Asset Usage

### GitHub Social Preview
**File:** `social-preview.svg`
**Dimensions:** 1280x640px

Upload to: Repository Settings > Social Preview

### Open Graph Image
**File:** `og-image.svg`
**Dimensions:** 1200x630px

Use for:
- Website meta tags
- Social sharing (Twitter, LinkedIn, Facebook)
- Documentation sites

### README Banner
**File:** `banner.svg`
**Dimensions:** 1200x300px

Embed in README.md:
```markdown
![go-auth banner](./brand/banner.svg)
```

### Favicon
**File:** `favicon.svg`
**Dimensions:** 32x32px (scalable)

Convert to ICO/PNG for web use if needed.

---

## Logo Clear Space

Maintain clear space around the logo equal to the height of the key element (approximately 1/3 of total logo height).

```
┌─────────────────────────────┐
│                             │
│    ┌─────┐                  │
│    │ 🛡️  │  go-auth         │
│    └─────┘                  │
│                             │
└─────────────────────────────┘
     ↑ Clear space = key height
```

---

## Do's and Don'ts

### Do
- Use the provided SVG files for maximum quality
- Maintain aspect ratios when scaling
- Use appropriate logo variant for context
- Keep clear space requirements
- Use brand colors consistently

### Don't
- Stretch or distort the logo
- Change logo colors arbitrarily
- Add effects (shadows, glows, 3D)
- Place logo on busy backgrounds
- Recreate the logo from scratch

---

## Color Accessibility

All color combinations meet WCAG 2.1 AA standards:

| Combination | Contrast Ratio | Rating |
|-------------|----------------|--------|
| White on Deep Navy | 15.2:1 | AAA |
| Go Cyan on Deep Navy | 6.8:1 | AA |
| Teal on Deep Navy | 7.1:1 | AA |
| Charcoal on White | 12.6:1 | AAA |

---

## Design Inspirations

This brand identity draws inspiration from:

| Source | Element Borrowed |
|--------|-----------------|
| **Go Programming Language** | Cyan color, developer-focused aesthetic |
| **Tailwind CSS** | Clean utility-first design language |
| **Vercel** | Sophisticated dark themes, minimal approach |
| **Stripe** | Professional trust signals, clear hierarchy |
| **1Password** | Shield/lock iconography excellence |
| **Auth0** | Security-focused but approachable tone |

---

## File Inventory

| File | Purpose | Dimensions |
|------|---------|------------|
| `logo-full.svg` | Primary logo with wordmark | 400x120 |
| `logo-icon.svg` | Shield icon only | 100x120 |
| `favicon.svg` | Browser favicon | 32x32 |
| `social-preview.svg` | GitHub social card | 1280x640 |
| `og-image.svg` | Open Graph sharing | 1200x630 |
| `banner.svg` | README header | 1200x300 |

---

## Contact

For brand-related questions or asset requests, open an issue on the [go-auth repository](https://github.com/meysam81/go-auth).

---

*Last updated: December 2024*
