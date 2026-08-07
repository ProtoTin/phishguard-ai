# Baseline Model Card

## Model summary

PhishGuard 0.4.0 contains two independent binary classification baselines:

- An email-text classifier using word and character TF-IDF features with
  class-balanced logistic regression.
- A URL classifier using separate hostname and path/query character TF-IDF
  representations, 14 offline lexical features, and a class-balanced stochastic
  logistic classifier.

Both models estimate the likelihood of the `phishing` class. They never visit,
resolve, crawl, or execute a submitted URL. Deterministic rules are evaluated as
comparators but are not included in the ML probability.

## Intended use

The models are intended for defensive education, offline experimentation,
portfolio demonstration, and later integration into an explainable risk-analysis
service. They are not approved for autonomous blocking, production email
filtering, user attribution, or claims that low-scoring content is safe.

## Training data

### Email model

- Training: 23,633 grouped and deduplicated records
- Validation: 6,033 grouped and deduplicated records
- Final test: 100 unique records from a separate external source
- Input: subject and body where available, otherwise message text

### URL model

- Training: 161,517 domain-grouped and deduplicated URLs
- Validation: 34,680 domain-grouped and deduplicated URLs
- Final test: 35,143 domain-grouped and deduplicated URLs
- Input: URL strings only

See the data card and data-quality report for provenance, label mapping,
deduplication, privacy, and source limitations.

### LinkedIn false-positive investigation

The PhiUSIIL source contains conflicting LinkedIn signals: the LinkedIn homepage is
labeled legitimate, while several LinkedIn short-link URLs are labeled phishing.
The previous whole-URL representation also learned path punctuation and hostname text
in the same feature space. Together, these artifacts caused a normal LinkedIn feed
URL to score 89/100. The component-aware model and exact-host policy safeguard address
that failure directly, and the policy build now checks both LinkedIn hostname forms
plus a malicious URL that contains `linkedin.com` only in its path.

## Model designs

### Email

- Word TF-IDF with one- and two-word n-grams
- Character-within-word TF-IDF with three- to five-character n-grams
- At most 50,000 features from each representation
- Class-balanced logistic regression
- Fixed random seed: `20260806`

### URL

- Separate hostname and path/query character TF-IDF branches with three- to
  five-character n-grams
- At most 50,000 character features per URL component
- Fourteen URL-only lexical measurements, including length, hostname structure,
  digits, punctuation, punycode, IP-host indicators, suspicious tokens, and
  character entropy
- Class-balanced stochastic gradient descent with logistic loss and averaging
- Fixed random seed: `20260806`

## Threshold selection

Thresholds are selected using validation data only. The pipeline checks values
from 0.05 through 0.95 and maximizes phishing-class F1. Recall and proximity to
0.5 break ties. The chosen threshold is then carried unchanged to the untouched
test set.

- Email threshold: 0.56
- URL threshold: 0.26

The low URL threshold shows why raw model probabilities must not be interpreted
as risk probabilities. The separate prevention policy uses validation-only
sigmoid calibration rather than these model-selection thresholds.

## Calibration and advisory policy

Each fitted baseline is frozen and calibrated with a sigmoid mapping on its
validation split. No test labels are used to train the model or calibrator. The
calibrated probability is rounded to a 0–100 risk score and mapped to four policy
bands: allow (0–29), warn (30–59), quarantine (60–84), and block (85–100). Policy
1.1 adds a documented probability ceiling for a short list of exact, well-known
HTTPS hosts. It does not trust lookalike domains, arbitrary subdomains, or a brand
name that merely appears in a path.

On the external email test, calibration reduced expected calibration error from
0.201642 to 0.170752 but increased Brier score from 0.131921 to 0.138143. This
mixed result is reported rather than hidden because calibration cannot correct
cross-source dataset shift. On the URL test, calibration reduced both Brier score
(0.005499 to 0.003067) and expected calibration error (0.018738 to 0.000857).
See the [explanation and prevention-policy evaluation](explanations-and-policy.md)
for the complete results.

## Evaluation results

| Model | Test set | Precision | Recall | F1 | PR-AUC | False-positive rate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Email ML | 100 | 0.5833 | 0.9130 | 0.7119 | 0.9229 | 0.1948 |
| Email rules | 100 | 1.0000 | 0.2174 | 0.3571 | 0.8326 | 0.0000 |
| URL ML | 35,143 | 0.9987 | 0.9934 | 0.9961 | 0.9989 | 0.000931 |
| URL rules | 35,143 | 1.0000 | 0.0134 | 0.0265 | 0.7506 | 0.0000 |

The ML models substantially improve recall over the conservative rules. The
email model's large validation-to-external-test drop is evidence of dataset shift
and is more important than its high in-source validation score.

## Limitations and risks

- The external email test contains only 23 unique phishing and 77 unique
  legitimate messages, so its estimates have high uncertainty.
- Email sources differ in time period, construction, and labeling practice.
- The curated Enron source may retain spam-versus-phishing ambiguity.
- Sender authentication, attachments, images, headers, and visible-link targets
  are absent from most email records.
- URL results may benefit from collection-specific artifacts even though domains
  do not cross splits.
- URL labels may become stale as domains and hosting change.
- The exact-host safeguard is intentionally small and manually reviewed; it is not
  a live reputation service, and a compromised legitimate site can still be risky.
- English dominates the email data; multilingual reliability is unknown.
- Attackers may evade character and lexical patterns through new domains,
  compromised legitimate sites, images, QR codes, or adversarial wording.
- Calibration is validation-specific and may not transfer to new campaigns,
  languages, time periods, or data sources.
- A low score is not proof of safety.

## Fairness and privacy

The datasets are not designed for demographic fairness evaluation, and the
models should not make decisions about people. Historical email data may contain
personal or organization-specific language. Raw data and trained artifacts are
excluded from Git, and evaluation reports contain aggregate statistics only.

## Artifact handling

Model artifacts are written to `artifacts/models/` and excluded from Git. Each
artifact's SHA-256 digest, size, Python version, NumPy version, and scikit-learn
version are recorded in `reports/model-evaluation.json`.

Calibrated artifacts are written to `artifacts/policy/` and are also excluded
from Git. Their SHA-256 digests and sizes are recorded in the versioned detection
policy and policy-evaluation report.

Joblib uses pickle-based deserialization. Load only artifacts generated by this
trusted local training workflow and verify their recorded digest first. Loading
an untrusted artifact can execute malicious code. Cross-version loading is not a
supported deployment strategy; models should be rebuilt from the pinned data and
training code.

## Future evaluation

- Recalibrate and re-evaluate when training data or deployment populations change.
- Add confidence intervals for the small external email test.
- Evaluate newer, multilingual, and campaign-separated email corpora.
- Add temporal and cross-source URL evaluation.
- Test homoglyphs, encoding tricks, shortened URLs, and benign security emails.
- Compare the baseline with a transformer only after the full service is working.
