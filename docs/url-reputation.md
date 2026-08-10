# URL Reputation and Input Normalization

## Why this layer exists

The lexical URL model estimates whether a string resembles its training examples. It
does not know that a domain belongs to a well-known organization, and it cannot prove
that a live page is currently safe. The PhiUSIIL source also contains brand names in
malicious paths and queries without necessarily containing the brand's canonical
hostname as a legitimate example. This caused false positives for LinkedIn and
YouTube.

## Reproducible popularity source

Policy 2.0 uses the first 1,000 pay-level domains from Tranco list `W3779`, generated on
August 9, 2026. The list aggregates CrUX, Farsight, Majestic, Cloudflare Radar, and
Cisco Umbrella rankings observed from July 11 through August 9, 2026. The project
stores the domain and rank pairs in code so portfolio builds are deterministic.

- List: https://tranco-list.eu/list/W3779/1000000
- Methodology: https://tranco-list.eu/methodology
- Packaged top-1,000 snapshot SHA-256:
  `a6643a3a179c11aa14db551e9595f7d4410528eadb02b0330b4893525bf6aa78`

Only an exact HTTPS hostname, after removing one optional `www` prefix, receives the
mitigation. Arbitrary subdomains and lookalike domains do not match. Popularity is not
a safety verdict: compromised popular sites and open redirects remain possible.

## Unverified domains

An unknown hostname without an IP host, obscuring `@` symbol, or multiple
credential-related terms is classified as `unverified`. Its effective score is bounded
to 30–59, and the user is told that no live reputation check occurred. Concrete
phishing evidence can still produce a phishing verdict, including for a popular host;
popularity never overrides corroborating warning signs.

## Missing schemes

When a user submits a bare domain such as `youtube.com`, the detector now analyzes
`https://youtube.com`. The response includes `assumed_https` evidence so the behavior
is visible. Explicit `http://` input remains HTTP and receives no reputation
mitigation.

## Production path

A production-grade deployment should combine the offline model with a continuously
updated malicious-URL feed. Google Safe Browsing supports checking URLs against
Google's unsafe-resource lists for non-commercial use, but it requires credentials
and has privacy and network implications. This portfolio version keeps analysis
offline and documents that limitation rather than silently transmitting submitted
URLs.
