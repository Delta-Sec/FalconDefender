# 🤝 Contributing to FalconDefender

<p align="center">
  <img src="https://img.shields.io/badge/Status-Contributions%20Welcome!-brightgreen?style=flat-square" alt="Contributions Welcome!">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License: MIT">
</p>

First off, thank you for considering contributing to **FalconDefender**! This project is driven by the community, and every contribution helps make it a more powerful and stable tool for threat detection and automation.

This document provides guidelines for contributing, whether it's through reporting a bug, suggesting a new feature, or submitting code.

## 📜 Code of Conduct

Before contributing, please take a minute to read our **[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)**. We enforce this code strictly to ensure that the FalconDefender community remains a professional, welcoming, and inclusive environment for everyone.

---

<details>
  <summary><strong>Table of Contents</strong></summary>
  <ol>
    <li><a href="#-how-can-i-contribute">How Can I Contribute?</a></li>
    <li><a href="#%EF%B8%8F-setting-up-your-development-environment">Setting Up Your Development Environment</a></li>
    <li><a href="#-pull-request-pr-workflow">Pull Request (PR) Workflow</a></li>
    <li><a href="#%EF%B8%8F-coding-style-guides">Coding Style Guides</a></li>
  </ol>
</details>

---

## 💡 How Can I Contribute?

### 🐞 Reporting Bugs

If you find a bug, please **open a new Issue** on our GitHub repository. A good bug report is essential for us to fix it. Please include:

* **A clear, descriptive title:** e.g., "Daemon fails to restart after system reboot." or "Scanner hangs on large PDF files."
* **Your Environment:** What OS (e.g., Ubuntu 22.04), Python version (e.g., 3.10), and YARA version are you using?
* **Steps to Reproduce:** Provide a clear, step-by-step guide on how to trigger the bug.
* **Expected Behavior:** What did you expect to happen?
* **Actual Behavior:** What happened instead? (Include full terminal output, logs from `falcon_daemon`, or screenshots).

### ✨ Suggesting Enhancements or New Features

We'd love to hear your ideas! Please **open a new Issue** and use the "Feature Request" template (if available).

* **Describe the feature:** What should it do? Why is it needed?
* **Pitch the solution:** How do you imagine it working?
* **Provide context:** How does this fit into the existing FalconDefender architecture (e.g., is this a new Scheduler task, a TUI improvement, or a new Reporting format)?

---

## 🛠️ Setting Up Your Development Environment

FalconDefender is a Python-based system with components for CLI, TUI, and background services.

### Local Setup

To start working on `app.py` (TUI), `cli.py`, `falcon_daemon.py`, or the core scanning engine:

```bash
# 1. Clone the repository
git clone [https://github.com/Delta-Security/falcon-defender.git](https://github.com/Delta-Security/falcon-defender.git)
cd falcon-defender

# 2. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# or .\venv\Scripts\activate on Windows

# 3. Install dependencies
pip install -r requirements.txt
```

> Note: Ensure you have yara-python and build tools installed as per the main README requirements.

## Running Tests
Before submitting, please ensure the core components are working:

```bash
# Run the TUI to check interface
python3 -m falcon.cli tui

# Run a test scan
python3 -m falcon.cli scan .
```

## 🚀 Pull Request (PR) Workflow
Ready to submit your code? Follow these steps to ensure a smooth review process.

1) **Fork the Repository:** Create your own copy of Delta-Security/falcon-defender.
2) **Create a Feature Branch:** Branch off main to keep your changes isolated.
```bash
git checkout -b feature/smart-scan-optimization
```

3) **Commit Your Changes:** Make your changes and write clear, descriptive commit messages.
```bash
git commit -m "feat(scanner): Add multithreading support for large directories"
git commit -m "fix(tui): Resolve flickering issue in log view"
```
4) **Push to Your Branch:**
```bash
git push origin feature/smart-scan-optimization
```
5) Open a Pull Request (PR):

* Go to the main FalconDefender repository and click "New Pull Request".

* Provide a clear title and a detailed description of your changes.

* Explain what you changed and why.

* If you are fixing an existing issue, link it (e.g., "Closes #33").

## ✍️ Coding Style Guides
To maintain consistency in the codebase, we adhere to the following styles:

Python: We follow PEP 8. Please run a linter (like `flake8` or `pylint`) over your code before submitting.

Type Hinting: We encourage the use of Python type hints for new functions and classes to improve readability.

By contributing to FalconDefender, you agree that your contributions will be licensed under its [MIT License](https://github.com/Delta-Sec/FalconDefender/blob/main/LICENSE).
