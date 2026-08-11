# Dashboard Guide

## Overview

PhishGuard 0.5.0 adds a responsive security-workbench interface at `/`. It is
served by the same FastAPI process as the analysis API, so the dashboard uses the
real verified email and URL models without a separate proxy or mock service.

## Analysis flow

1. Select email content or website URL.
2. Paste untrusted content or load the clearly labeled example.
3. Run the analysis.
4. Review the calibrated 0–100 risk score, classification, and advisory action.
5. Inspect controlled warning signs and optional model-level supporting and
   mitigating features.

The interface never displays the submitted content after analysis. Values from
the response are inserted with safe text operations rather than HTML rendering.

## Design decisions

- The first screen prioritizes the analyzer instead of generic dashboard chrome.
- The dark green visual system communicates defensive security without relying
  on fear-based imagery or hacker clichés.
- Empty, loading, error, and completed-result states are distinct.
- Email and URL modes include content-specific examples, help text, limits, and
  character counts.
- Results visually separate the calibrated score, policy recommendation,
  human-readable reasons, and model-level feature contributions.
- Privacy, offline URL handling, and advisory limitations remain visible before
  and after analysis.

## Accessibility and browser safety

- Semantic landmarks, labels, live regions, a skip link, visible focus states,
  keyboard-operable tabs, and reduced-motion behavior are included.
- The layout adapts for desktop, tablet, and narrow mobile screens.
- A restrictive Content Security Policy allows scripts, styles, images, and API
  connections only from the same origin.
- Analysis responses use `Cache-Control: no-store`; the UI does not use browser
  storage or third-party scripts.
- Framing, camera, microphone, and geolocation access are disabled by response
  headers.

## Current boundary

The dashboard is available through the public Render demo and the same reviewed
container used locally. The free deployment uses process-local rate limiting and
provider health checks; it does not claim distributed edge throttling, enterprise
availability, or authentication for future administrative capabilities.
