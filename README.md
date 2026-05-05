# OWASP Scanner

**Biztonsági tesztelő eszköz az OWASP Top 10:2025 alapján**

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010%202025-orange.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

## Tartalomjegyzék

- [Beüzemelés](#-beüzemelés)
- [Használat](#-használat)
- [Modulok](#-modulok)
- [Példa kimenet](#-példa-kimenet)
- [Tesztelési célpontok](#-tesztelési-célpontok)
- [OWASP Top 10:2025](#-owasp-top-102025)
- [Hibaelhárítás](#-hibaelhárítás)

---

## Beüzemelés

### Előfeltételek

- **Python 3.10+** (ajánlott: 3.11 vagy 3.12)
- **pip** (Python csomagkezelő)

### Virtuális környezet (ajánlott)

```bash
# Létrehozás
python -m venv venv

# Aktiválás Windows-on:
venv\Scripts\activate

# Aktiválás Linux/Mac-en:
source venv/bin/activate
```

### Függőségek telepítése

```bash
pip install -r requirements.txt
```

### Telepítés ellenőrzése

```bash
python main.py --version
```

---

## Használat

### Alapvető scan

```bash
python main.py scan --target https://example.com
```

### Csak bizonyos modulok

```bash
# Csak endpoint discovery
python main.py scan -t https://example.com -m endpoint

# Csak header analysis
python main.py scan -t https://example.com -m headers
```

### Összes opció

```bash
python main.py scan --help
```

```
Options:
  -t, --target TEXT       Target URL to scan [required]
  -m, --modules TEXT      Modules: endpoint,headers,all (default: all)
  -o, --output TEXT       Output format: json,html,both (default: both)
  --output-dir TEXT       Output directory (default: ./reports)
  -r, --rate-limit FLOAT  Requests per second (default: 2.0)
  --timeout INTEGER       Request timeout in seconds (default: 10)
  --crawl-depth INTEGER   Maximum crawl depth (default: 3)
  --no-bruteforce         Disable path bruteforcing
  -y, --yes               Skip confirmation prompt
  -v, --verbose           Enable verbose output
  --help                  Show this message and exit.
```

### Példák

```bash
# Gyors scan megerősítés nélkül
python main.py scan -t https://example.com -y

# Részletes output
python main.py scan -t https://example.com -v

# Csak JSON riport
python main.py scan -t https://example.com -o json

# Bruteforce nélkül (gyorsabb)
python main.py scan -t https://example.com --no-bruteforce

# Lassabb rate limit (óvatosabb)
python main.py scan -t https://example.com -r 1.0
```

### Kapcsolat tesztelése

```bash
python main.py test-connection -t https://example.com
```

### OWASP kategóriák megjelenítése

```bash
python main.py info
```
