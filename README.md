# IsItSecure? 🔒

A comprehensive password security scanner that analyzes password strength and checks breach exposure using privacy-preserving techniques.

## Features

- **Password Strength Analysis**: Comprehensive evaluation including length, complexity, entropy, and pattern detection
- **Breach Database Integration**: Uses HaveIBeenPwned API with k-anonymity for privacy protection
- **Batch Processing**: Analyze multiple passwords efficiently
- **Privacy-First Design**: Never stores or logs raw passwords
- **CLI Tool**: Easy-to-use command-line interface
- **JSON Export**: Machine-readable results for integration
- **Actionable Recommendations**: Clear suggestions for improvement

## Installation

### From PyPI
```bash
pip install isitsecure
```

### From Source
```bash
git clone https://github.com/yourusername/isitsecure.git
cd isitsecure
pip install -e .
```

### Dependencies
```bash
pip install -r requirements.txt
```

## Usage

### CLI Commands

#### Check Single Password
```bash
# Interactive mode
isitsecure check

# Direct password input
isitsecure check --password "YourPassword123!"

# Skip breach check (faster)
isitsecure check --password "YourPassword123!" --no-breach

# JSON output
isitsecure check --password "YourPassword123!" --json

# Export results
isitsecure check --password "YourPassword123!" --output examples/report.json
```

#### Batch Analysis
```bash
# Check multiple passwords from file
isitsecure batch --file examples/sample_passwords.txt

# Export batch results
isitsecure batch --file examples/sample_passwords.txt --output examples/batch_report.json

# Skip breach checks for faster processing
isitsecure batch --file examples/sample_passwords.txt --no-breach
```

#### Generate Secure Passwords
```bash
# Generate 3 secure password suggestions
isitsecure generate

# Generate custom number of suggestions
isitsecure generate --count 5
```

#### Demo Mode
```bash
# Run demonstration with sample passwords
isitsecure demo
```

### Using as a Library

```python
from isitsecure import PasswordScanner

scanner = PasswordScanner()

# Analyze single password
result = scanner.scan_password('MyPassword123!', {
    'check_breaches': True,
    'format': 'json'
})

# Batch analysis
passwords = ['password1', 'StrongP@ss!2024', 'weak123']
results = scanner.scan_batch(passwords)

# Generate suggestions
suggestions = scanner.generate_suggestions(5)
```

## File Formats

### Password Input File
Create a text file with one password per line:
```
password123
MyStr0ng!P@ssw0rd
admin
letmein
```

### JSON Output Format
```json
{
  "report_info": {
    "created_by": "IsItSecure",
    "project_url": "https://github.com/chrismat-05/IsItSecure"
  },
  "timestamp": "2025-08-27T11:31:14.068148",
  "version": "1.0.0",
  "results": [
    {
      "analysis": {
        "password": "YourPassword123!",
        "length": 16,
        "strength": {
          "length": {
            "score": 100,
            "feedback": "Excellent length",
            "length": 16
          },
          "complexity": {
            "score": 100,
            "feedback": "High complexity"
          },
          "uniqueness": {
            "score": 100,
            "feedback": "Appears unique"
          }
        },
        "entropy": 104.87,
        "composition": {
          "has_lowercase": true,
          "has_uppercase": true,
          "has_digits": true,
          "has_symbols": true,
          "has_spaces": false,
          "lowercase_count": 10,
          "uppercase_count": 2,
          "digit_count": 3,
          "symbol_count": 1
        },
        "weaknesses": [],
        "suggestions": [
          "Use a unique password for each account",
          "Enable two-factor authentication where possible"
        ],
        "score": 100,
        "risk_level": "Low"
      },
      "breach_data": {
        "is_breached": true,
        "breach_count": 2,
        "risk_level": "Low"
      },
      "timestamp": "2025-08-27T11:31:14.059156"
    }
  ]
}
```

## Security & Privacy

- **No Data Storage**: Passwords are never stored or logged
- **K-Anonymity**: Uses SHA-1 hash prefixes for breach checks (only first 5 characters sent to API)
- **Rate Limiting**: Built-in delays between API requests to respect service limits

## 📊 Analysis Criteria

- **Strength Score (0-100)**: Based on length, complexity, entropy, blacklist, patterns
- **Risk Level**: Low, Medium, High, Critical
- **Breach Exposure**: Yes/No, number of exposures
- **Suggestions**: Actionable tips and passphrase ideas

---

## 🤝 Contributing

Pull requests, issues, and feature suggestions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📜 License

MIT License. See [LICENSE.txt](LICENSE.txt) for details.

---

## 👤 Credits

Created by Chris. Inspired by best practices in cybersecurity and privacy.