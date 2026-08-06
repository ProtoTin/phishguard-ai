# Project Scope

## 1. Purpose

The AI Phishing Detection and Prevention System is a defensive application that
analyzes user-submitted email content and URLs. It helps a user recognize likely
phishing attempts by returning an explainable risk assessment and a recommended
response.

The first release is a portfolio-quality demonstration rather than a production
email gateway. The project emphasizes a complete engineering workflow:
reproducible data preparation, defensible evaluation, secure input handling,
explainable predictions, testing, packaging, and documentation.

## 2. Intended users

### Primary user: individual recipient

A person who received a suspicious message and wants a fast, understandable
assessment before clicking a link or responding.

### Secondary user: security analyst or reviewer

A technical user who wants to inspect the signals behind a result, test known
samples, and review model performance.

### Portfolio reviewer

An employer or engineer evaluating the project's software design, ML practices,
security decisions, tests, and documentation.

## 3. Core user stories

- As a user, I can paste a URL and receive a risk score without the application
  opening the URL.
- As a user, I can paste an email's subject, body, sender, and visible links and
  receive an assessment.
- As a user, I can understand the main warning signs behind the assessment.
- As a user, I receive a practical recommendation: allow with caution, warn,
  quarantine, or block.
- As an analyst, I can see which model version produced a result.
- As a developer, I can recreate the approved dataset and model artifacts from
  documented commands.
- As a reviewer, I can run the application and automated tests locally.

## 4. Inputs

### Email analysis

- Subject text
- Plain-text or untrusted HTML body
- Claimed sender address
- Optional display name
- URLs extracted from or supplied with the message
- Optional attachment filenames, but not attachment contents in the MVP

### URL analysis

- One URL supplied as text

The application will impose length limits and reject malformed or unsupported
input safely.

## 5. Outputs

Each analysis will return:

- A classification: `legitimate`, `suspicious`, or `phishing`
- A risk score from 0 to 100
- A confidence or uncertainty indication
- Human-readable reasons for the result
- A recommended action: `allow`, `warn`, `quarantine`, or `block`
- The model and policy version used

The output language will avoid guarantees. In particular, `legitimate` means
that the submitted content did not cross the configured warning threshold; it
does not mean that the content has been proven safe.

## 6. MVP functional requirements

The MVP must:

1. Accept email fields and standalone URLs through a command-line tool and API.
2. Parse URLs without making network requests to them.
3. Extract documented text, sender, and URL features.
4. Combine deterministic rules with trained baseline models.
5. Return a versioned, explainable risk assessment.
6. Support configurable decision thresholds.
7. Include automated tests for parsing, features, inference, and API behavior.
8. Include reproducible data preparation and model-training commands.
9. Provide a web interface using sanitized text output.
10. Run locally using documented setup instructions and containers.

## 7. Non-functional requirements

### Security

- Never automatically visit a user-submitted URL.
- Never execute attachments or embedded content.
- Treat email HTML and model output as untrusted when displayed.
- Do not place secrets, raw messages, or credentials in logs.
- Validate input types and enforce size limits.
- Separate administrative and public capabilities.

### Privacy

- Do not retain submitted email bodies by default.
- Use synthetic or licensed samples in demonstrations and tests.
- Remove or transform personal data during dataset preparation.
- Make any future feedback collection explicit and opt-in.

### Reproducibility

- Pin major dependencies.
- Record dataset sources, licenses, and preparation steps.
- Version model artifacts, feature schemas, and decision policies.
- Set random seeds where appropriate.

### Performance

- Target a p95 analysis time below one second for the classical local baseline,
  excluding initial service startup.
- Place explicit limits on request size and processing time.

### Accessibility and usability

- Do not communicate risk through color alone.
- Present concise explanations suitable for nontechnical users.
- Provide safe example inputs for an immediate demonstration.

## 8. Detection scope

The initial system will look for:

- Credential harvesting and password-reset lures
- Brand, executive, and sender impersonation signals
- Mismatches between claimed sender identity and sender domain
- Suspicious URL structure, encoding, and obfuscation
- Pressure, urgency, fear, reward, invoice, and payment language
- Requests for credentials, payment, gift cards, or sensitive information
- HTML forms and misleading link text in supplied email content
- Suspicious attachment filenames and risky extensions as metadata

## 9. Explicitly out of scope for the MVP

- Opening URLs, crawling websites, or downloading remote content
- Executing or sandboxing attachments
- Malware binary classification
- Live mailbox access or automatic deletion of messages
- Browser-extension interception
- Full SMTP gateway integration
- DNS, WHOIS, certificate, or threat-intelligence lookups
- Image-based or QR-code phishing detection
- Multilingual performance guarantees
- Fully autonomous blocking in a real organization
- Claims of production certification or complete phishing protection

These may be considered only after the offline MVP is complete and evaluated.

## 10. Decision policy

Initial policy thresholds are design defaults and must be tuned on validation
data:

| Risk score | Classification | Recommended action |
| ---: | --- | --- |
| 0-29 | Legitimate | Allow with normal caution |
| 30-59 | Suspicious | Warn and request manual review |
| 60-84 | Phishing | Recommend quarantine |
| 85-100 | Phishing | Recommend block |

The model estimates risk; the policy converts that score into an action. Keeping
these concerns separate allows thresholds to change without retraining a model.

## 11. Success criteria

The MVP is complete when:

- A fresh clone can be installed and run from the README.
- Data preparation and model training are reproducible.
- Tests and security checks run automatically on proposed changes.
- The untouched test set contains no known duplicates from training data.
- Results report precision, recall, F1, PR-AUC, false-positive rate, confusion
  matrix, calibration, latency, and model size.
- A decision threshold and its tradeoffs are documented instead of selected
  solely for maximum accuracy.
- Every assessment includes understandable reasons and version information.
- The browser demo works with synthetic samples and does not render unsafe HTML.
- Known limitations and expected failure modes are documented prominently.

Numerical performance targets will be set after the datasets and honest test
split are established. Setting them earlier would encourage optimizing to an
unknown or potentially leaky benchmark.

## 12. Portfolio completion criteria

The public repository should demonstrate:

- Meaningful, incremental commits and tagged releases
- A clear architecture diagram and screenshots
- A data card and model card
- Baseline-versus-advanced-model comparisons
- Automated tests and continuous integration
- A concise demonstration video or hosted demo
- Security, privacy, and responsible-use decisions
- A backlog of realistic future improvements

## 13. Deferred decisions

The following will be resolved in their relevant phases:

- Exact licensed datasets and label-mapping rules
- Baseline feature definitions and algorithms
- Risk-score calibration method and final thresholds
- Frontend framework and hosting provider
- Whether an advanced transformer meaningfully improves the baseline
- Whether privacy-preserving feedback storage is valuable for the demo
