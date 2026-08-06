# Data Card

## Dataset summary

The Phase 2 dataset supports two related binary tasks:

- Classify submitted email text as `legitimate` or `phishing`.
- Classify a submitted URL string as `legitimate` or `phishing` without visiting
  or resolving it.

The repository does not redistribute source or processed records. A versioned
manifest downloads publisher-hosted artifacts and verifies every file before
processing. Only attribution, integrity metadata, code, and aggregate reports
are committed.

## Sources

### Primary email development pool

**Phishing Email Curated Datasets — `Enron.csv`** by Champa, Rabbi, and
Zibran, Zenodo DOI `10.5281/zenodo.8339691`.

- License: CC BY 4.0
- Dataset release: 2023; associated paper: 2024
- Supplied records: 29,767 subject-and-body email records
- Published labels: `0` legitimate and `1` phishing
- Role: model training and validation only
- Split grouping: normalized email subject where present
- Caution: the collection incorporates historical Enron-derived email and may
  contain personal or organization-specific language

### Supplemental email development pool

**Multiclass NLP Dataset for Phishing and Social Engineering Threat Detection**
by Engineering Ingegneria Informatica Spa, Zenodo DOI
`10.5281/zenodo.15235123`.

- License: CC BY 4.0
- Published: 2025
- Supplied records: 624 anonymized English messages
- Binary inclusion: `Phishing` and `NOT-Malicious General Class` only
- Exclusion: Malware, Scareware, Baiting, and Pretexting retain distinct source
  meanings and are not silently relabeled as phishing
- Role: model training and validation only

### Email external test pool

**Phishing validation emails dataset** by Radoslav Miltchev, Dimitar Rangelov,
and Evgeni Genchev, Zenodo DOI `10.5281/zenodo.13474746`.

- License: CC BY 4.0
- Published: 2024
- Supplied records: 2,000 safe and phishing messages
- Composition: a mixture of real-world and artificially generated emails as
  described by the creators
- Role: external testing only; no records are used for model selection

### URL development pool

**PhiUSIIL Phishing URL (Website) Dataset** by Arvind Prasad and Shalini
Chandra, UCI Machine Learning Repository.

- License: CC BY 4.0
- Published: 2024
- Supplied records: 235,795 URLs
- Published labels: `1` legitimate and `0` phishing
- Role: grouped training, validation, and test splits
- Runtime-compatible fields retained: raw URL text and label
- Excluded fields: webpage content, WHOIS, similarity, and other features that
  would require live retrieval or create train/serve skew

## Normalized schema

Each processed JSON Lines record contains:

| Field | Meaning |
| --- | --- |
| `id` | Stable canonical content fingerprint prefix |
| `content_type` | `email` or `url` |
| `text` | Original normalized email or URL text |
| `label` | `legitimate` or `phishing` |
| `source` | Source-manifest identifier |
| `source_record_id` | Original row number for local auditing |
| `group_id` | Hashed split-group identifier |
| `split` | `train`, `validation`, `test`, or `external_test` |

## Preparation

1. Verify exact byte length and MD5 or SHA-256 digest.
2. Parse each publisher-specific schema.
3. Normalize line endings and remove null characters.
4. Map only explicitly declared source labels.
5. Exclude empty rows and out-of-scope labels.
6. Canonicalize content for near-exact duplicate detection.
7. Remove same-label duplicates and all label-conflicting fingerprints.
8. Assign deterministic splits from a fixed seed.
9. Keep every URL domain group in a single split.
10. Write aggregate quality reports without record contents.

## Leakage controls

- Deduplication runs across all sources before split assignment.
- External email test records take no part in model development.
- URL rows are grouped by their published domain value before hashing into a
  split, preventing an identical domain group from appearing across partitions.
- The seed and algorithm are versioned, so reruns produce identical assignments.

These controls reduce but do not eliminate semantic or campaign-level leakage.
The email sources do not provide reliable campaign identifiers or timestamps.

## Privacy and safety

- Raw and processed content is excluded from Git.
- Reports contain counts and provenance but no message or URL samples.
- Dataset URLs are inert strings. The pipeline never visits, resolves, or
  executes them.
- Users should not open dataset URLs manually; some may be malicious.
- The external email dataset may contain a mixture of real and synthetic text.
  Local files should be handled as potentially sensitive research data.

## Known limitations

- The supplemental binary email pool is small after preserving source-label
  semantics.
- English is the only documented email language.
- Source datasets may contain synthetic, outdated, or source-specific patterns.
- The curated Enron file may inherit spam-versus-phishing ambiguity from its
  underlying corpora even though the curated release describes a phishing task.
- Dataset class balance does not represent real inbox prevalence.
- URL labels describe the creators' collection period and may become stale.
- Domain grouping is based on the source's `Domain` field rather than a current
  public-suffix lookup.
- Canonical deduplication catches formatting-level near duplicates, not every
  semantic paraphrase or related campaign.
- Email body-only records do not provide reliable sender headers, attachment
  metadata, or visible-versus-target link pairs.

## Intended use

Appropriate uses include reproducible education, baseline model development,
offline evaluation, and defensive portfolio demonstration. The data and models
are not sufficient for autonomous production blocking, attribution, or claims
that a low-scoring message is safe.

## Maintenance

Source artifacts are checksum-pinned. A publisher change must be reviewed and
recorded as an explicit manifest update, never accepted automatically. The data
card and quality report must be regenerated whenever sources, label mappings,
deduplication, or split logic changes.
