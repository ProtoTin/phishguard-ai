# Security Policy

## Supported versions

This project is pre-release software. Security fixes are applied only to the
latest code on the `main` branch until the first stable release.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. When this repository
is published, use GitHub's private vulnerability-reporting feature. Until then,
contact the repository owner privately.

Include a description, affected component, reproduction steps, potential
impact, and any suggested mitigation. Do not include real credentials, private
email content, or harmful payloads beyond what is necessary to demonstrate the
issue safely.

## Project boundaries

The service is a defensive portfolio project, not a production security
gateway. Submitted URLs must never be fetched by the core analysis path, and
email HTML must never be rendered directly.
