<div align="center">

███████╗ █████╗ ██╗      ██████╗ ██████╗ ███╗   ██╗  
██╔════╝██══██╗██║     ██╔════╝██╔═══██╗████╗  ██║  
█████╗  ███████║██║     ██║     ██║   ██║██╔██╗ ██║  
██╔══╝  ██══██║██║     ██║     ██║   ██║██║╚██╗██║  
██║     ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║  
╚═╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝  

**By Delta Security**

</div>

# 🦅 FalconDefender 2.0.0

**FalconDefender 2.0.0** is an advanced, daemon-powered cybersecurity system for **threat detection, response, and automation**.  
Built with Python, it leverages **YARA** for high-performance signature matching and includes a **persistent scheduler**, a **secure quarantine database**, and both a **Text-based User Interface (TUI)** and **Command-Line Interface (CLI)**.

> This is not just a scanner; it is a full-featured, persistent security service designed for continuous monitoring and management.

---

## 🌟 Core Features

### 🧩 Daemon-Powered Scheduler
- Runs as a background service (`falcon_daemon.py`) using **APScheduler** and **SQLAlchemy**.
- Ensures scans and updates continue even after reboot.

### 💻 Dual Interface (TUI & CLI)
- **Interactive TUI (`app.py`)** – Real-time dashboard for monitoring, logs, and scheduling.  
- **Full CLI (`cli.py`)** – Scriptable, automation-ready control system.

### ⚡ High-Performance Engine
- **Concurrent scanning** with `ThreadPoolExecutor` for parallel file checks.  
- **Optimized rule management** with precompiled YARA caches (`.yarac`).  
- **Incremental and smart scanning** (checks modified files only).

### 🔒 Secure Quarantine Vault
- Isolates threats in a protected directory.
- Uses an **SQLite database** (`quarantine.db`) to log metadata, hashes, and timestamps.

### 📄 Comprehensive Reporting
- On-demand plain-text or **PDF reports**.
- **Email delivery via SMTP (TLS)** to security admins.

### 🧠 Service Installation
- Built-in CLI commands:
  - `install-service`
  - `uninstall-service`
- Registers `falcon_daemon` as a **systemd** service for 24/7 operation.

### 🔁 Secure Updater
- Safely updates YARA rules or program components.
- Supports **SHA256 checksum** verification for integrity.

---

## 🏗️ Architecture Overview

```mermaid
graph TD
    subgraph User Interaction
        User(User)
        User -- "falcon.cli tui" --> TUI[TUI (app.py)]
        User -- "falcon.cli [command]" --> CLI[CLI (cli.py)]
    end

    subgraph System Services (Daemon)
        Daemon[Falcon Daemon (falcon_daemon.py)]
        Daemon -- "Manages" --> Scheduler[APScheduler]
        Scheduler -- "Triggers" --> ScanTask(Scheduled Scan)
        Scheduler -- "Triggers" --> UpdateTask(Scheduled Update)
    end

    subgraph Core Components
        Scanner[Scanner (scanner.py)]
        YaraManager[Yara Manager (yara_manager.py)]
        Quarantine[Quarantine Mgr (quarantine.py)]
        Updater[Updater (updater.py)]
        ReportMgr[Report Mgr (report.py)]
    end

    subgraph Data Stores
        Config[config.json]
        Rules[YARA Rules (.yar)]
        Cache[Compiled Rules (.yarac)]
        QuarantineDB[(Quarantine DB<br>quarantine.db)]
        SchedulerDB[(Scheduler DB<br>scheduler.sqlite)]
    end

    CLI -- "Controls" --> Daemon
    TUI -- "Controls & Views" --> Daemon
    CLI -- "Uses" --> Core Components
    TUI -- "Uses" --> Core Components
    Daemon -- "Uses" --> Core Components

    ScanTask -- "Uses" --> Scanner
    ScanTask -- "Uses" --> ReportMgr
    UpdateTask -- "Uses" --> Updater

    Scanner -- "Reads" --> YaraManager
    Scanner -- "Writes" --> Quarantine
    YaraManager -- "Reads/Writes" --> Rules
    YaraManager -- "Reads/Writes" --> Cache
    Quarantine -- "Writes" --> QuarantineDB
    Scheduler -- "Writes" --> SchedulerDB
    Core Components -- "Read" --> Config
```

---

## 📁 Project Structure

```
falcon-defender/
├── falcon/
│   ├── app.py              # Text-based User Interface (TUI)
│   ├── cli.py              # Command-Line Interface (CLI)
│   ├── config.py           # ConfigurationManager (handles config.json)
│   ├── quarantine.py       # QuarantineManager (handles SQLite DB)
│   ├── report.py           # ReportManager (PDF, Email)
│   ├── scheduler.py        # SchedulerManager (APScheduler)
│   ├── scheduled_tasks.py  # Functions for the scheduler to run
│   ├── scanner.py          # Core YARA scanning engine
│   ├── tui_integration.py  # TUI to Core bridge
│   ├── updater.py          # Secure rule & program updater
│   ├── utils.py            # Platform-specific helpers
│   └── yara_manager.py     # YARA rule compiler & cache manager
├── falcon_daemon.py        # Persistent background service
├── rules/                  # YARA rule files
├── config.json             # Main configuration file
├── requirements.txt
├── README.md
└── MIGRATION_GUIDE.md
```

---

## 📦 Installation

### Prerequisites
- Python 3.8+
- `yara-python`
- `build-essential` or `Visual C++ Build Tools`
- Dependencies in `requirements.txt`

### 1️⃣ From Source (Recommended)
```bash
git clone https://github.com/Delta-Security/falcon-defender.git
cd falcon-defender
python3 -m venv venv
source venv/bin/activate   # Linux/macOS
.env\Scriptsctivate    # Windows
pip install -r requirements.txt
```

Add your `.yar` rules to the `rules/` directory.

**First Run:**
```bash
python3 -m falcon.cli tui
```

### 2️⃣ As a Persistent Service (Linux/systemd)
```bash
sudo python3 -m falcon.cli install-service
systemctl status falcon-scheduler.service
journalctl -u falcon-scheduler.service -f
sudo python3 -m falcon.cli uninstall-service
```

---

## 🛠️ Usage

### 1. Interactive TUI
```bash
python3 -m falcon.cli tui
```
Monitor scans, view logs, and manage schedules.

### 2. Command-Line Examples

#### Scanning
```bash
python3 -m falcon.cli scan /var/www
python3 -m falcon.cli scan /home/user/file.zip --quarantine-matches
python3 -m falcon.cli scan / --output-pdf --email-report
```

#### Scheduler
```bash
python3 -m falcon.cli schedule add   --name "daily_home_scan"   --task scan   --cron-expression "0 0 3 * * *"   --task-args '["/home/user"]'   --task-kwargs '{"quarantine_matches": true}'
```

#### Quarantine
```bash
python3 -m falcon.cli quarantine list
python3 -m falcon.cli quarantine restore 15
python3 -m falcon.cli quarantine delete 16
```

#### Updates
```bash
python3 -m falcon.cli update-rules --source file:///opt/new-rules.zip
python3 -m falcon.cli update-rules   --source https://rules.example.com/latest.zip   --checksum "a1b2c3d4..."
```

---

## ⚙️ Configuration

Example `config.json`:
```json
{
    "scanner_threads": 8,
    "max_file_size_mb": 100,
    "blocked_extensions": [".tmp", ".log", ".bak"],
    "allowed_extensions": [],
    "yara_timeout": 60,
    "quarantine_dir": "/home/user/.local/share/falcondefender/quarantine",
    "rules_dir": "/home/user/.local/share/falcondefender/rules",
    "report_dir": "/home/user/.local/share/falcondefender/reports",
    "email_reporting": {
        "enabled": false,
        "smtp_server": "smtp.example.com",
        "smtp_port": 587,
        "smtp_username": "your_email@example.com",
        "sender_email": "falcondefender@example.com",
        "recipient_emails": ["security_admin@example.com"],
        "use_tls": true
    }
}
```

---

## 📜 License
Licensed under the **MIT License**.  
See the `LICENSE` file for full terms.

---

<div align="center">

🦅 **FalconDefender 2.0.0 — By Delta Security**  
**Advanced. Persistent. Secure.**

</div>
