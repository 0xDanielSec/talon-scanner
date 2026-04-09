# Glasswing Scanner

A Python-based scanner project.

## Requirements

- Python 3.10+

## Setup

```bash
chmod +x setup.sh
./setup.sh
```

Or manually:

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

```bash
python glasswing.py --help
python glasswing.py --config configs/config.yaml --output reports/
```

## Project Structure

```
glasswing-scanner/
├── glasswing.py          # Entry point
├── src/                  # Source modules
├── configs/
│   └── config.yaml       # Default configuration
├── reports/              # Scan output
├── .github/
│   └── workflows/
│       └── ci.yml        # GitHub Actions CI
├── requirements.txt
├── setup.sh
└── .gitignore
```

## Development

```bash
# Lint
ruff check .
black .

# Tests
pytest --cov=src
```
