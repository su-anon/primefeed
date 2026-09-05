---
name: Zero-Knowledge Cryptographic & Threat Telemetry Architecture
colors:
  surface: '#0f131c'
  surface-dim: '#0f131c'
  surface-bright: '#353942'
  surface-container-lowest: '#0a0e16'
  surface-container-low: '#181c24'
  surface-container: '#1c2028'
  surface-container-high: '#262a33'
  surface-container-highest: '#31353e'
  on-surface: '#dfe2ee'
  on-surface-variant: '#bec8d2'
  inverse-surface: '#dfe2ee'
  inverse-on-surface: '#2c3039'
  outline: '#88929b'
  outline-variant: '#3e4850'
  surface-tint: '#89ceff'
  primary: '#89ceff'
  on-primary: '#00344d'
  primary-container: '#0ea5e9'
  on-primary-container: '#003751'
  inverse-primary: '#006591'
  secondary: '#4edea3'
  on-secondary: '#003824'
  secondary-container: '#00a572'
  on-secondary-container: '#00311f'
  tertiary: '#4cd7f6'
  on-tertiary: '#003640'
  tertiary-container: '#00aac6'
  on-tertiary-container: '#003943'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#c9e6ff'
  primary-fixed-dim: '#89ceff'
  on-primary-fixed: '#001e2f'
  on-primary-fixed-variant: '#004c6e'
  secondary-fixed: '#6ffbbe'
  secondary-fixed-dim: '#4edea3'
  on-secondary-fixed: '#002113'
  on-secondary-fixed-variant: '#005236'
  tertiary-fixed: '#acedff'
  tertiary-fixed-dim: '#4cd7f6'
  on-tertiary-fixed: '#001f26'
  on-tertiary-fixed-variant: '#004e5c'
  background: '#0f131c'
  on-background: '#dfe2ee'
  surface-variant: '#31353e'
typography:
  display-xl:
    fontFamily: spaceGrotesk
    fontSize: 48px
    fontWeight: '700'
    lineHeight: 52px
    letterSpacing: -0.04em
  display-xl-mobile:
    fontFamily: spaceGrotesk
    fontSize: 32px
    fontWeight: '700'
    lineHeight: 36px
    letterSpacing: -0.03em
  headline-lg:
    fontFamily: spaceGrotesk
    fontSize: 32px
    fontWeight: '600'
    lineHeight: 38px
    letterSpacing: -0.02em
  headline-lg-mobile:
    fontFamily: spaceGrotesk
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 30px
    letterSpacing: -0.02em
  headline-md:
    fontFamily: spaceGrotesk
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
    letterSpacing: -0.01em
  headline-sm:
    fontFamily: spaceGrotesk
    fontSize: 18px
    fontWeight: '600'
    lineHeight: 24px
    letterSpacing: 0em
  body-lg:
    fontFamily: spaceMono
    fontSize: 15px
    fontWeight: '400'
    lineHeight: 24px
    letterSpacing: -0.01em
  body-md:
    fontFamily: spaceMono
    fontSize: 13px
    fontWeight: '400'
    lineHeight: 20px
    letterSpacing: 0em
  body-sm:
    fontFamily: spaceMono
    fontSize: 11px
    fontWeight: '400'
    lineHeight: 16px
    letterSpacing: 0.02em
  label-code:
    fontFamily: spaceMono
    fontSize: 12px
    fontWeight: '700'
    lineHeight: 16px
    letterSpacing: 0.08em
  telemetry-micro:
    fontFamily: spaceMono
    fontSize: 9px
    fontWeight: '700'
    lineHeight: 12px
    letterSpacing: 0.12em
spacing:
  grid-step: 4px
  space-2xs: 2px
  space-xs: 4px
  space-sm: 8px
  space-md: 16px
  space-lg: 24px
  space-xl: 32px
  space-2xl: 48px
  space-3xl: 64px
  gutter-mobile: 12px
  gutter-desktop: 16px
  panel-padding-compact: 12px
  panel-padding-spacious: 24px
---

## Brand & Style

The design system embodies an uncompromising cypherpunk terminal architecture combined with geometric constructivism and persistent monospaced cryptographic payload telemetry. Built for operational security, cryptographic transparency, and high-stakes intelligence analysis, it eliminates frivolous decoration, skeuomorphic noise, and gratuitous radius softenings.

### Brand Personality & Philosophy
- **Mathematical Determinism:** Every interface decision reflects cryptographic auditability. If an element exists, it communicates state, telemetry, or verified data payloads.
- **Terminal Constructivism:** Sharp architectural partitions, orthogonal wireframes, exposed grid ticks, and monospace-driven hierarchy transform consumer interfaces into hardened operational consoles.
- **Austere Precision:** The visual atmosphere evokes high-security air-gapped workstations, hardware security module logs, and classified threat feeds. Contrast is razor-sharp, text is legible at machine density, and structural boundaries are absolute.

### Design Movement & Aesthetic Form
The style fuses **Brutalist Terminal Architecture** with **Cybernetic Structuralism**:
- Pure orthogonal layout rules with rigid zero-radius edges (`roundedness: 0`).
- Heavy reliance on monospaced telemetry tracks, coordinate readouts, cryptographic hashes, and visual framing reticles.
- High-contrast monochromatic foundations paired with an authoritative, laser-focused primary cyan-blue wavelength (`#0EA5E9`) and cryptographically designated status states.

## Colors

The color palette is built strictly for high-contrast dark environments, establishing visual authority, verified cryptographic integrity, and immediate fault detection.

### Core Architecture
- **Primary (`#0EA5E9`):** Telemetry blue. Drives interactive system focus, cursor coordinates, primary terminal commands, and structural grid highlights.
- **Secondary (`#10B981`):** Cryptographic verification emerald. Reserved exclusively for authenticated signatures, valid HMAC validation states, and zero-knowledge proof verifications.
- **Tertiary (`#06B6D4`):** Active telemetry cyan. Applied to streaming IoC threat vectors, cryptographic key fingerprints, and dynamic live data streams.
- **Neutral Foundation (`#0B0F17`):** Non-reflective void black/slate. Eliminates glare, maintains deep visual anchor depth, and hosts micro-contrast structural panels (`#070A0F` base, `#111827` panel elevation).

### Cryptographic State Tokens
- **Verified / Validated (`#10B981`):** Confirmed block receipt, verified Ed25519 signature, passing HMAC.
- **Tamper Alert / Compromised (`#F43F5E`):** Checksum failure, broken chain verification, invalid signature packet, active payload intrusion.
- **Encrypted Payload / Ciphertext (`#6366F1`):** GCM envelope, unparsed raw hex streams, zero-knowledge witness state.
- **Key Lifecycle Alert / Ephemeral (`#F59E0B`):** Key expiration pending, stale certificate, revoking session authority.

### Monochromatic Contrast Accents
- **Text Dominant:** `#F8FAFC` (pure terminal output, high readability).
- **Text Subdued:** `#94A3B8` (metadata labels, layout headers, frame indices).
- **Frame & Divider Strokes:** `#1E293B` (structural border delineation) and `#334155` (active container boundaries).

## Typography

The typographical engine combines the rigid geometric rhythm of **Space Grotesk** for architectural framing titles with the austere, mechanical precision of **Space Mono** for body copy, analytical intelligence records, and cryptographic telemetry.

### Typographic Rules
- **Proportional vs Fixed Alignment:** Structural module titles and overarching console views utilize Space Grotesk. Intelligence streams, zero-knowledge proofs, post payloads, and terminal outputs rely entirely on Space Mono to retain column integrity across arbitrary bitstreams.
- **Case Conventions:** Metadata indicators, security headers, protocol statuses, and system commands must be rendered in `UPPERCASE` with positive tracking (`letter-spacing: 0.08em` to `0.12em`).
- **Tabular Data Fidelity:** Numeric figures, SHA-256 digests, and threat indicators must never re-flow. Every monospace glyph occupies an identical optical footprint, preventing layout jitter during real-time telemetry streaming.

## Layout & Spacing

The layout is engineered as a rigid, modular instrument deck utilizing an unrelenting 4px architectural grid. Interfaces do not float dynamically over nebulous whitespace; they slot securely into defined constructivist partitions separated by razor-thin borders.

### The Modular Grid Framework
- **Desktop (>= 1280px):** 12-column or 16-column fixed structural grid. 16px borders/gutters. Layouts feature left-anchored key navigation / hardware status trees, central decrypted stream / analysis canvases, and right-rail threat intelligence/validation feeds.
- **Tablet (768px - 1279px):** 8-column layout. Peripheral data streams dock into collapsible horizontal drawers or secondary tabs.
- **Mobile (< 768px):** 4-column layout with strict 12px structural margins. Navigation transforms into an indexed top-anchored command header. High-density data tables become vertically partitioned data blocks.

### Constructivist Boundary Guidelines
- Panels are contiguous; they abut against each other separated by `1px solid #1E293B` strokes rather than floating on wide margins.
- System metrics and telemetry coordinates (e.g., `SEC_LVL // 04`, `HMAC_OK: [99.8%]`) occupy corner notches and module headers using `space-xs` and `space-sm` offsets.

## Elevation & Depth

This design system deliberately eschews soft drop shadows, blurred ambient lighting, and skeuomorphic depth. Depth is expressed purely via **chromatic stratification**, **opaque planar layering**, and **crisp 1px perimeter outlines**.

### Depth Hierarchy
1. **Base Ground (Level 0 - `#070A0F`):** The terminal foundation. Unfocused backdrop space, canvas gutters, and non-interactive grid planes.
2. **Structural Deck (Level 1 - `#0B0F17`):** Primary workspaces, raw feed streams, message threads, and data logs. Enclosed by `1px solid #1E293B`.
3. **Elevated Monoliths (Level 2 - `#111827`):** Selected cards, active threat intelligence payloads, input modules, and command panels. Surrounded by `1px solid #334155` or accented by `1px solid #0EA5E9` when targeted.
4. **Focused Modals & Overlays (Level 3 - `#0F172A`):** Hardware token prompts, signature verification dialogs, and critical key revocation warnings. Framed with high-contrast dual-tone borders (`1px solid #0EA5E9` interior, `1px solid #070A0F` perimeter) with zero blur.

### Reticle & Corner Ticks
To reinforce mechanical constructivism, active focus surfaces feature synthetic terminal crosshairs or 4px inverted corner notches (`+` markings on grid intersections) rendered in primary `#0EA5E9` instead of ambient shadows.

## Shapes

The geometric architecture of the system is strictly sharp: `roundedness: 0`. 

### Shape Directives
- **Zero Radius Enforcement:** Every boundary—buttons, input fields, notification banners, payload containers, popovers, and badges—features an unyielding `0px` border-radius.
- **Chamfer & Cut Accents (Optional Structural Geometry):** High-priority cryptographic action triggers or verified authentication stamps may utilize 45-degree corner chamfers (`polygon clip-path`) measuring exactly 6px or 8px across opposite diagonals, creating an austere hardware silhouette.
- **Line Hierarchy:** Borders are consistently `1px` uniform solid vectors. Interactive focus rings are double-offset hard borders (`1px solid #0EA5E9` separated by a 1px `#070A0F` gap).

## Components

### 1. Buttons & Triggers
- **Primary Execution Button:** Solid `#0EA5E9` background, `#070A0F` text (Space Mono, uppercase, bold). `0px` radius. Hover shifts background to `#38BDF8`. Active state reverses contrast.
- **Cryptographic Action Button (Sign / Verify):** Border `1px solid #10B981`, background transparent, text `#10B981`. Hover state floods with `rgba(16, 185, 129, 0.1)`.
- **Destructive / Revoke Button:** Border `1px solid #F43F5E`, text `#F43F5E`, background transparent. Hover state floods with `rgba(244, 63, 94, 0.12)`.
- **System Command Trigger:** Neutral outline `1px solid #334155`, text `#94A3B8`. Left-aligned with command prefix: `> EXEC_PUBKEY`.

### 2. Cryptographic Badges & State Chips
- **Verified HMAC / Signature Badge:** Compact block container. Background `rgba(16, 185, 129, 0.1)`, border `1px solid #10B981`, text `#10B981` in `telemetry-micro`. Prefixed with `[✓ VERIFIED]`.
- **Tamper Alert Badge:** Background `rgba(244, 63, 94, 0.15)`, border `1px solid #F43F5E`, text `#F43F5E`. Prefixed with `[! CORRUPT_SIG]`.
- **Ciphertext Payload Tag:** Background `rgba(99, 102, 241, 0.1)`, border `1px solid #6366F1`, text `#A5B4FC`. Accompanied by byte-length indicator (e.g., `ENC::2048_BYTES`).
- **Key Expiry Pill:** Border `1px solid #F59E0B`, text `#F59E0B`, background transparent. Indicates time-to-live (`TTL: 00:14:02`).

### 3. Inputs & Command Consoles
- **Terminal Input Field:** Background `#070A0F`, border `1px solid #1E293B`, text `#F8FAFC`. Space Mono typography with persistent flashing terminal block cursor (`#0EA5E9`).
- **Focus State:** Border changes directly to `1px solid #0EA5E9`. No glow or shadow.
- **Prefix / Coordinate Slot:** Left-anchored static container displaying protocol markers (e.g., `sha256:`, `msg_in:`, `auth_key:`) in `#475569`.

### 4. Checkboxes & Radio Selectors
- **Checkbox:** Square `14px x 14px` enclosure with `0px` radius. Unchecked: `1px solid #334155`, background `#070A0F`. Checked: Inset solid square filled with `#0EA5E9`.
- **Radio Selector:** Diamond/rhombus shaped or sharp square with inner nested block indicator. No rounded circles.

### 5. Cards & Intelligence Enclosures
- **IoC Feed / Message Container:** Background `#0B0F17`, stroke `1px solid #1E293B`.
- **Header Bar:** Contiguous title banner separated by `1px solid #1E293B`, containing panel coordinate references (e.g., `SEC_FEED // 0x4A`) in `telemetry-micro` text.
- **Tamper State Override:** If an enclosure contains a verified hash mismatch, the entire border switches to `1px solid #F43F5E`, and the header displays a persistent warning strobe ribbon.

### 6. Specialized Cryptographic Components
- **Payload Hex Inspector:** Two-column monospace stream with left column memory offsets (`0x0000` to `0x00F0` in `#475569`) and right column byte sequences (`#F8FAFC`), supporting character-range selection highlights in `#0EA5E9`.
- **Key Fingerprint Visualizer:** Monospace sequence formatted in 4-character blocks separated by colons (`E2A4:79B1:...`), highlighting high-entropy bits with contrasting tint colors.