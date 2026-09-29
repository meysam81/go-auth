# go-auth Brand Guidelines

## Brand Identity

**go-auth** is a comprehensive, modular, and production-ready authentication library for Go applications. The visual identity reflects the core values of **security**, **modularity**, and **professional trust**.

---

## Logo

### Primary Mark

The go-auth logo consists of a **shield icon** combined with a **wordmark**. The shield represents security and protection, while its layered construction symbolizes the modular architecture of the library.

#### Logo Variants

| File | Usage |
|------|-------|
| `logo-full-dark.svg` | Full logo on dark backgrounds |
| `logo-full-light.svg` | Full logo on light backgrounds |
| `logo-icon.svg` | Icon only (dark backgrounds) |
| `logo-icon-light.svg` | Icon only (light backgrounds) |
| `logo-wordmark-dark.svg` | Wordmark only (dark backgrounds) |
| `logo-wordmark-light.svg` | Wordmark only (light backgrounds) |

### Clear Space

Maintain a minimum clear space around the logo equal to the height of the letter "g" in the wordmark.

### Minimum Size

- **Full logo**: Minimum width 200px
- **Icon only**: Minimum width 32px
- **Wordmark**: Minimum width 120px

---

## Color Palette

### Primary Colors

| Name | Hex | RGB | Usage |
|------|-----|-----|-------|
| **Go Cyan** | `#00ADD8` | 0, 173, 216 | Primary brand color, accents |
| **Deep Navy** | `#0F172A` | 15, 23, 42 | Dark backgrounds, text on light |
| **Electric Teal** | `#06B6D4` | 6, 182, 212 | Secondary accent |

### Supporting Colors

| Name | Hex | RGB | Usage |
|------|-----|-----|-------|
| **Cyan 600** | `#0891B2` | 8, 145, 178 | Light background variant |
| **Cyan 700** | `#0E7490` | 14, 116, 144 | Darker accent |
| **Sky** | `#22D3EE` | 34, 211, 238 | Highlights, gradients |

### Neutral Colors

| Name | Hex | RGB | Usage |
|------|-----|-----|-------|
| **Slate 900** | `#0F172A` | 15, 23, 42 | Primary dark |
| **Slate 800** | `#1E293B` | 30, 41, 59 | Secondary dark |
| **Slate 500** | `#64748B` | 100, 116, 139 | Muted text |
| **Slate 400** | `#94A3B8` | 148, 163, 184 | Light text on dark |
| **Slate 50** | `#F8FAFC` | 248, 250, 252 | Light backgrounds, text on dark |

---

## Typography

### Primary Font

**System UI Stack** (for maximum compatibility):

```css
font-family: system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
```

### Font Weights

| Weight | Usage |
|--------|-------|
| **700 (Bold)** | Headings, "go" and "auth" in wordmark |
| **500 (Medium)** | Subheadings, tagline |
| **400 (Regular)** | Body text |
| **300 (Light)** | The hyphen in "go-auth" |

### Code Font

For code contexts, use **JetBrains Mono** or system monospace.

---

## Iconography

### Shield Concept

The shield icon uses three concentric layers to represent:

1. **Outer layer** (most transparent): The overall security boundary
2. **Middle layer**: The authentication layer
3. **Inner layer** (most opaque): The protected core
4. **Keyhole**: The authentication mechanism

### Design Principles

- **Geometric precision**: Clean, mathematical shapes
- **Layered depth**: Gradients and opacity create depth
- **Modular feel**: Separate layers suggest pluggable components

---

## Assets

### Favicon

| File | Size | Usage |
|------|------|-------|
| `favicon.svg` | Scalable | Browser tab, app icons |

### Social Media

| File | Dimensions | Usage |
|------|------------|-------|
| `social-preview.svg` | 1280 x 640 | GitHub repository card |
| `og-image.svg` | 1200 x 630 | Open Graph (Twitter, LinkedIn) |

### Documentation

| File | Dimensions | Usage |
|------|------------|-------|
| `banner.svg` | 1200 x 300 | README header |

---

## Tagline

**"Secure. Modular. Go."**

Use this tagline consistently across marketing materials. It encapsulates:
- **Secure**: Core purpose - authentication and security
- **Modular**: Key differentiator - pluggable, interface-based design
- **Go**: Target ecosystem - the Go programming language

---

## Usage Guidelines

### Do

- Use the provided SVG files for scalability
- Maintain the color palette consistency
- Keep adequate clear space around the logo
- Use appropriate variants for light/dark backgrounds

### Don't

- Stretch or distort the logo
- Change the logo colors outside the palette
- Add effects (shadows, outlines) to the logo
- Use the logo at sizes smaller than minimum
- Place the logo on busy backgrounds without contrast

---

## File Inventory

```
assets/branding/
├── BRAND-GUIDELINES.md    # This file
├── banner.svg             # README header banner
├── favicon.svg            # Browser favicon
├── logo-full-dark.svg     # Full logo (dark bg)
├── logo-full-light.svg    # Full logo (light bg)
├── logo-icon.svg          # Icon only (dark bg)
├── logo-icon-light.svg    # Icon only (light bg)
├── logo-wordmark-dark.svg # Wordmark only (dark bg)
├── logo-wordmark-light.svg# Wordmark only (light bg)
├── og-image.svg           # Open Graph image
└── social-preview.svg     # GitHub social preview
```

---

## Contact

For brand-related questions or to request additional assets, please open an issue at [github.com/meysam81/go-auth](https://github.com/meysam81/go-auth).
