# PhishGuard – Phishing Email Detection Platform

## Description

A Django-based phishing email detection platform developed using Python, Object-Oriented Programming (OOP), and web technologies. The project provides an automated tool to inspect incoming emails, analyze potential threat indicators such as suspicious links and deceptive language, and compute an interpretable risk score to assist users in identifying phishing attacks.

> **Status:** Project is currently under active development. Core components and detection engine modules are being implemented incrementally.

---

## Main Components

- **Django Web Application:** Web interface and service layer managing user interactions and analysis requests.
- **Python-based Phishing Detection Engine:** Modular, decoupled engine implementing OOP principles to inspect emails independently of the web framework.
- **Frontend Dashboard:** User interface for submitting raw emails and viewing scan reports.
- **Email Analysis and Classification:** Heuristic scoring pipeline classifying emails as Safe, Suspicious, or Phishing.

---

## Planned Detection-Engine Functionality

- **Email Parsing:** Extraction of email headers, metadata, plain-text body, and HTML content from raw RFC 822 messages.
- **URL Extraction:** Identification of HTTP and HTTPS links from message bodies and HTML anchor tags.
- **Suspicious URL Analysis:** Detection of IP addresses, URL shorteners, excessive length, misleading `@` symbols, and risky domains.
- **Email Content Analysis:** Rule-based detection of phishing indicators such as urgency, credential harvesting, threats, and financial requests.
- **Risk Scoring:** Transparent heuristic scoring mechanism combining URL, header, and content indicators into a bounded 0–100 risk score.
- **Email Classification:** Categorization into discrete threat levels (Safe, Suspicious, Phishing) based on configurable thresholds.

---

## Technologies

- **Python** (v3.10+)
- **Django** (v5.0+)
- **Object-Oriented Programming** (Abstraction, Encapsulation, Inheritance, Polymorphism, Composition)
- **Python Standard Library** (`email`, `urllib.parse`, `re`, `abc`, `dataclasses`)
- **HTML5**
- **CSS3**
- **JavaScript**
- **pytest**
