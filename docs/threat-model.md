# Threat Model

## 1. Scope and security objective

This threat model covers the portfolio application's ingestion, parsing,
classification, explanation, and display of user-supplied email content and
URLs.

The primary objective is to provide a useful phishing-risk assessment without
allowing hostile input to cause network access, code execution, data exposure,
or misleading claims of safety.

## 2. Assets to protect

- User-submitted email content and sender information
- Application secrets and deployment credentials
- Model artifacts and feature schemas
- Training, validation, and test data integrity
- Prediction and evaluation integrity
- Service availability
- User trust in explanations and recommended actions

## 3. Trust boundaries

All submitted content is untrusted. This includes:

- Email subjects and bodies
- HTML markup
- URLs and domain names
- Sender names and addresses
- Attachment filenames
- User feedback and labels
- Model artifacts obtained outside the controlled training workflow
- Third-party datasets

The public interface, API, processing service, stored artifacts, and any future
administrative interface are separate trust zones. Data crossing between them
must be validated and minimized.

## 4. Adversaries

### Phishing author

Attempts to evade detection with spelling changes, Unicode confusables,
redirects, URL encoding, benign-looking text, prompt-like instructions, or
adversarial phrasing.

### Malicious public user

Submits oversized, malformed, or crafted content to trigger denial of service,
injection, parser failures, network access, or sensitive logging.

### Data poisoner

Attempts to place mislabeled or duplicated samples into training or feedback
data so future models become less reliable.

### Opportunistic attacker

Searches the public repository or deployed service for credentials, unsafe
defaults, outdated dependencies, exposed administrative functions, or verbose
error messages.

## 5. Major threats and controls

### Unsafe network access

A submitted URL could target localhost, a private service, or cloud metadata.
The analysis path will perform offline lexical parsing only and prohibit network
retrieval.

### Cross-site scripting

An email body could contain scripts, event handlers, or dangerous HTML. The
interface will never render raw email HTML. It will display escaped or sanitized
text and use a restrictive content security policy.

### Code or command injection

Crafted content could reach a shell, template, or unsafe parser. The application
will avoid shell interpolation, validate structured input, and use safe parsing
libraries with fixed execution paths.

### Denial of service

Large messages, deeply nested markup, or repeated requests could exhaust the
service. Controls will include request-size, parsing-time, and rate limits,
bounded feature extraction, and timeouts.

### Sensitive-data or credential exposure

Private messages could appear in logs, or API keys could be committed to Git.
The application will avoid raw-content retention, redact logs, disable verbose
production errors, use environment-based secrets, and enable secret scanning.

### Model evasion and incorrect decisions

Homoglyphs, inserted whitespace, or obfuscated URLs could bypass features. The
detector will use character features, careful normalization, adversarial tests,
and layered rules. Calibrated thresholds, uncertainty language, false-positive
measurement, and manual review will reduce harm from incorrect decisions.

### Data poisoning and evaluation leakage

Untrusted feedback could corrupt training data, while related campaigns in both
training and test data could inflate results. Feedback will be quarantined for
review. Dataset preparation will track provenance, remove exact and fuzzy
duplicates, and group splits by domain, campaign, source, or time where possible.

### Artifact or dependency compromise

A replaced model or vulnerable package could alter system behavior. Controls
will include versioned and hashed artifacts, compatibility checks, locked
dependencies, automated scanning, minimal packages, and reviewed updates.

### Explanation manipulation and prompt injection

Email content could be presented as trusted application text or contain
instructions aimed at an optional language model. The interface will visually
separate quoted input from controlled explanations. The baseline will not use
free-form LLM decisions, and all content will be treated as data.

### Formula injection

Exported values could begin with spreadsheet formula characters. Any future CSV
or spreadsheet export will escape dangerous prefixes.

## 6. Abuse cases

The system must safely handle:

- A URL pointing to `localhost`, private IP space, or a cloud metadata address
- A multi-megabyte email body
- Invalid percent encoding and malformed Unicode
- Punycode and Unicode-confusable hostnames
- Mixed visible-link text and actual link destinations
- HTML containing scripts, event handlers, forms, and embedded resources
- A message containing instructions aimed at the classifier or an LLM
- Repeated automated submissions intended to exhaust service capacity
- Feedback that deliberately applies the wrong label
- An old or incompatible model artifact loaded by the API

These cases will become concrete automated tests during implementation.

## 7. ML-specific risks

### Distribution shift

Phishing campaigns change over time, so historical benchmark performance may
not represent current attacks. Evaluation should include source-separated or
time-aware testing where the data permits it.

### Class imbalance

Real-world phishing prevalence differs from balanced research datasets. Report
precision-recall metrics and evaluate thresholds under plausible prevalence,
not only on a 50/50 dataset.

### Spurious correlations

The model may learn dataset artifacts, brands, formatting, or source-specific
tokens instead of phishing behavior. Compare performance by source and inspect
important features.

### Overconfidence

Raw classifier scores are not automatically reliable probabilities. Calibrate
scores on validation data and communicate uncertainty.

### Explanation mismatch

A plausible explanation may not reflect why the model produced its score.
Baseline explanations should be tied to observed rules or model features, and
the interface must distinguish rule evidence from model-level evidence.

## 8. Privacy decisions

- Raw submissions are processed in memory and discarded by default.
- Logs contain operational metadata, not full email bodies or complete URLs.
- Demonstrations use synthetic or properly licensed data.
- Training data provenance and licenses are documented.
- Any future storage or feedback feature requires explicit consent, retention
  limits, and deletion behavior.

## 9. Residual risk

Even with these controls, the system can misclassify new or carefully crafted
attacks. Offline URL analysis cannot determine whether a destination currently
hosts malicious content. The application is a decision-support tool and should
be one layer in a broader security process.

## 10. Security validation checklist

Before a public deployment:

- [ ] Confirm the analysis path performs no outbound requests
- [ ] Enforce request-size, rate, and processing-time limits
- [ ] Escape or sanitize every displayed user-controlled value
- [ ] Verify raw input is absent from normal logs
- [ ] Run unit, integration, malformed-input, and adversarial tests
- [ ] Scan dependencies, containers, and repository history for secrets
- [ ] Require authentication for administrative capabilities
- [ ] Verify model artifacts and feature-schema compatibility at startup
- [ ] Document evaluated thresholds and false-positive tradeoffs
- [ ] Provide a clear reporting path for security issues

This threat model will be updated whenever a new trust boundary is introduced,
including external threat-intelligence services, feedback storage, mailbox
integration, browser extensions, or live URL retrieval.
