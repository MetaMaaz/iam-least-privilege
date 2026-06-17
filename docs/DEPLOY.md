# Publishing to GitHub

Step-by-step to get this repo live with a green CI badge. Two routes: the
GitHub CLI (`gh`, fastest) or the web UI. Pick one for step 4.

## 0. Prerequisites (one-time)

```bash
git --version          # macOS ships with git; if missing: xcode-select --install
gh --version           # optional but easiest: brew install gh && gh auth login
```

Make sure the project folder is on your Mac, then open Terminal in it:

```bash
cd ~/path/to/iam-least-privilege
```

## 1. Sanity-check it runs before you publish

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q                                   # expect: 19 passed
python cli.py report --in data/mock_account.json --out output/
```

`.venv/` is already in `.gitignore`, so it won't be committed.

## 2. Personalise two placeholders

- In `README.md`, replace `USERNAME` in the CI badge URL with your GitHub
  username.
- `LICENSE` already says "Maaz Hussain" — change the year/name if you like.

## 3. Initialise git with a clean commit history

A short, themed history reads better to recruiters than one giant commit. This
uses Conventional Commits and mirrors the build order:

```bash
git init -b main

# 1) project scaffold
git add README.md LICENSE .gitignore requirements.txt .github docs
git commit -m "chore: project scaffold, CI, license, docs"

# 2) data model + mock account
git add analyzer/__init__.py analyzer/models.py data/mock_account.json
git commit -m "feat(models): inventory data model + vulnerable mock IAM account"

# 3) rules
git add data/sensitive_actions.yaml data/escalation_rules.yaml
git commit -m "feat(data): sensitive-action and privilege-escalation rule catalogues"

# 4) classifier
git add analyzer/classifier.py tests/__init__.py tests/conftest.py tests/test_classifier.py
git commit -m "feat(classifier): privilege tiers, sensitivity, wildcard detection"

# 5) analyzer + risk scoring
git add analyzer/analyzer.py tests/test_analyzer.py
git commit -m "feat(analyzer): findings across six categories + risk scoring"

# 6) escalation engine
git add analyzer/escalation.py tests/test_escalation.py
git commit -m "feat(escalation): privilege-escalation path graph with before/after diff"

# 7) recommender
git add analyzer/recommender.py
git commit -m "feat(recommender): tightened least-privilege policy generation"

# 8) reporter, ingestion, CLI
git add analyzer/reporter.py analyzer/ingestion.py cli.py ingest
git commit -m "feat(report): markdown report, mermaid diagram, AWS ingestion, CLI"

# 9) sample output
git add output
git commit -m "docs: commit sample generated report and remediation policies"
```

Prefer one commit? Just `git add -A && git commit -m "feat: AWS IAM least-privilege analyzer"`.

## 4. Create the GitHub repo and push

### Option A — GitHub CLI (recommended)

```bash
gh repo create iam-least-privilege --public --source=. --remote=origin --push
```

That creates the repo, wires the remote, and pushes in one go.

### Option B — Web UI

1. Go to <https://github.com/new>.
2. Name it `iam-least-privilege`, set **Public**, do **not** add a README/license
   (you already have them), then **Create repository**.
3. Back in Terminal:

```bash
git remote add origin https://github.com/USERNAME/iam-least-privilege.git
git push -u origin main
```

## 5. Confirm CI runs

- Open the repo → **Actions** tab. The `CI` workflow runs automatically on push.
- It lints (ruff), runs pytest on Python 3.10–3.12, and smoke-tests the pipeline.
- Once it's green, the badge at the top of the README turns green too.

## 6. Polish the repo page (5 minutes, high impact)

- Add a **description**: "Explainable, rules-based AWS IAM least-privilege
  analyzer — finds privilege-escalation paths and generates tightened policies
  (NIST 800-207 / AWS best practice)."
- Add **topics**: `aws`, `iam`, `cloud-security`, `least-privilege`,
  `privilege-escalation`, `security-tools`, `python`, `nist-800-207`.
- The Mermaid diagram and tables in `README.md` and `output/report.md` render
  natively on GitHub — check they look right.
- **Pin** the repo on your profile (Profile → Customize your pins).

## 7. Updating later

```bash
git add -A
git commit -m "feat: <what changed>"
git push
```

CI re-runs on every push and pull request.

---

### Note: this is a CLI tool, not a hosted service

There's nothing to "deploy" to a server — the deliverable is the repository and
the committed sample report. If you later want the report viewable as a web
page, enable **Settings → Pages** and point it at a folder, or convert
`output/report.md` to HTML. Not required for a portfolio piece.
