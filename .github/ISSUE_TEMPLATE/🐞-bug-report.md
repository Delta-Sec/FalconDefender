---
name: "\U0001F41E Bug Report"
about: Create a report to help us improve FalconDefender
title: ''
labels: bug
assignees: AyhamAsfoor

---

**Thank you for helping improve FalconDefender! To help us fix this bug, please provide the following details.**

### 1. Clear Bug Description
(A clear and concise description of what the bug is. Example: "The daemon crashes with a 'Database Locked' error when trying to view logs in the TUI while a scheduled scan is running.")

### 2. Steps to Reproduce
(Please provide a clear, step-by-step guide on how to trigger the bug. This is the most important part!)

1.  Run `sudo python3 -m falcon.cli install-service` to start the daemon.
2.  Open the TUI using `python3 -m falcon.cli tui`.
3.  Navigate to the '📜 [LOGS]' tab.
4.  Wait for the scheduled scan to trigger...
5.  **BUG:** The TUI freezes and the daemon service stops.

### 3. Expected Behavior
(A clear description of what you expected to happen.)

* I expected the TUI to remain responsive and display new log entries in real-time while the background scan continues without interruption.

### 4. Actual Behavior (The Bug)
(A description of what actually happened. **Please paste all terminal output, error messages, and logs here.** Use a code block for clarity.)

```text
Paste your error logs here...
```

### 5. Your Development Environment
(This is critical for us to debug. Please fill out all relevant fields.)

* **Operating System:** (e.g., Ubuntu 22.04 LTS, Arch Linux)

* **Python Version:** (e.g., Python 3.10.12)

* **YARA Version:** (Run pip show yara-python. e.g., v4.3.1)

* **FalconDefender Version:** (e.g., v2.0.0)

* Installation Type:

   * [ ] Systemd Service (Installed via install-service)

   * [ ] Standalone/Manual (Ran manually via falcon_daemon.py)

   * [ ] Virtual Environment (Yes/No)

### 6. Additional Context
(Add any other context about the problem here. For example: "This only happens when scanning large PDF files," or "I recently migrated from v1.5 using the migration guide.")
