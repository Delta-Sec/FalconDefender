---
name: "✨ Feature Request"
about: Suggest an idea or new functionality for FalconDefender
title: ''
labels: enhancement
assignees: AyhamAsfoor

---

**Thank you for helping us make FalconDefender even better!**

To help us understand your idea, please provide as much detail as possible.

---

<h2 style="color: #007ACC; border-bottom: 2px solid #007ACC; padding-bottom: 10px;">
  Is your feature request related to a problem?
</h2>

(A clear and concise description of what the problem is. *Example: "I am frustrated when... because..."*)

*Example: "I am frustrated because the scanner generates a PDF report for every single scan, filling up my disk. I only need reports when threats are actually found."*

---

<h2 style="color: #4CAF50; border-bottom: 2px solid #4CAF50; padding-bottom: 10px;">
  Describe the solution you'd like
</h2>

(A clear and concise description of what you want to happen.)

*Example: "I would like a new option in `config.json` (e.g., `reporting.only_on_threat: true`) that prevents report generation if the scan result is clean."*

---

<h2 style="color: #FFC107; border-bottom: 2px solid #FFC107; padding-bottom: 10px;">
  Describe alternatives you've considered
</h2>

(A clear and concise description of any alternative solutions or features you've considered.)

*Example: "I considered writing a cron job to manually delete empty PDF reports every night, but this is a hacky workaround and not native to the daemon."*

---

<h2 style="color: #9C27B0; border-bottom: 2px solid #9C27B0; padding-bottom: 10px;">
  Which component(s) does this affect?
</h2>

(Please check all that apply. This helps us route the request to the right place!)

- [ ] **🛡️ Daemon & Scheduler** (e.g., `falcon_daemon.py`, `scheduler.py`)
- [ ] **🔍 Core Scanner & YARA** (e.g., `scanner.py`, `yara_manager.py`)
- [ ] **🖥️ User Interface (TUI/CLI)** (e.g., `app.py`, `cli.py`, `tui_integration.py`)
- [ ] **📦 Quarantine & Data** (e.g., `quarantine.py`, `updater.py`, SQLite DB)
- [ ] **📄 Documentation** (e.g., `README.md`, `MIGRATION_GUIDE.md`)

---

<h2 style="color: #FF5722; border-bottom: 2px solid #FF5722; padding-bottom: 10px;">
  Additional Context
</h2>

(Add any other context, mockups, screenshots, or links here.)
