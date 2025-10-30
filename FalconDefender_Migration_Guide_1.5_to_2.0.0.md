Migration Guide: FalconDefender 1.5 to 2.0.0
Version 2.0.0 is a complete architectural rewrite of FalconDefender. It transitions the tool from a simple, single-file scanner (V1.5) into a persistent, multi-component security system (V2.0.0).
This guide provides the steps to migrate your V1.5 setup to the robust V2.0.0 architecture.

V1.5 vs V2.0.0: At a Glance
The change is significant. The old V1.5 was a single script; V2.0.0 is a full application suite.

Feature | FalconDefender 1.5 (Old) | FalconDefender 2.0.0 (New)
---------|--------------------------|-----------------------------
Architecture | Single .py script | Decoupled modules (scanner, scheduler, cli, app, etc.)
Interface | Basic text menu | Interactive TUI (textual) + Full-featured CLI
Scheduling | threading.Timer (In-memory, non-persistent) | Persistent Daemon (APScheduler + SQLAlchemy)
Service | Not supported | Built-in systemd service installer (falcon_daemon.py)
Quarantine | Simple file move to one folder | Secure Vault with SQLite Database (tracks hash, path, etc.)
YARA Rules | Re-compiled on every run | Compiled Rule Caching (.yarac) for instant startup
Reporting | Basic .txt file | Advanced PDF Reports and Email (SMTP) Alerts
Configuration | Hardcoded paths / basic .ini | Central config.json file for all components
Updates | Not supported | Secure, checksum-validated rule and program updates
Scanning | Single-threaded, recursive | Multi-threaded (Concurrent) with advanced filtering

Migration Flow
This diagram outlines the core steps you will need to take to migrate your old setup.

1. Backup V1.5 Data (Rules, Quarantine Vault)
2. Install V2.0.0 (Clone repo, install requirements.txt)
3. Configure V2.0.0 (Create new config.json, copy old settings)
4. Migrate YARA Rules (Copy old .yar files to new rules/ dir)
5. First Run (Run `python3 -m falcon.cli tui` to init databases)
6. Migrate Quarantine (Manually re-scan/quarantine old files)
7. Migrate Automation (Replace old cron/scripts with new Scheduler)
8. Install Service (Optional) (Run `install-service` command)
9. Migration Complete

Step-by-Step Migration Instructions

Step 1: Backup Your V1.5 Data
Before you begin, create a backup of your entire V1.5 project directory. Most importantly, back up:
- Your YARA rules folder (e.g., yara_rules/)
- Your Quarantine folder (e.g., Quarantine Folder/)
- Your old config.ini or any file where you stored settings.

Step 2: Install FalconDefender 2.0.0
Clone the new V2.0.0 repository into a new directory. Do not overwrite your V1.5 project.

git clone https://github.com/Delta-Security/falcon-defender.git v2-falcon
cd v2-falcon
pip install -r requirements.txt

Step 3: Configure V2.0.0
Run the TUI once to generate the default configuration file:

python3 -m falcon.cli tui

(Exit the TUI with Ctrl+C).
Locate the new config.json file (e.g., ~/.local/share/falcondefender/config.json).
Edit it to copy over relevant settings (thread counts, file size limits, etc.).
Set quarantine_dir, rules_dir, and report_dir paths.
If using email reporting, configure email_reporting and set FALCON_EMAIL_PASS environment variable.

Step 4: Migrate YARA Rules
Copy all your old .yar and .yara files from your V1.5 yara_rules/ folder into the new rules_dir.
FalconDefender will automatically compile and cache them into a .yarac file on the next run.

Step 5: Migrate the Quarantine (Manual but Necessary)
V2.0.0 uses an SQLite database to track quarantined files. You cannot just copy the old folder.
Move all files from your old Quarantine folder to a temporary directory.
Re-scan the directory with auto-quarantine enabled:

python3 -m falcon.cli scan ~/v1.5-quarantine-restore --quarantine-matches

This will migrate files to the new vault and log their metadata in quarantine.db.

Step 6: Migrate Automation (The Big Upgrade)
In V1.5, you likely used cron or Task Scheduler to run main.py.
Disable old automation.

Install the new V2.0.0 service (Linux only):
sudo python3 -m falcon.cli install-service

Then add scheduled tasks via CLI:

python3 -m falcon.cli schedule add \
    --name "daily_www_scan" \
    --task scan \
    --cron-expression "0 2 * * *" \
    --task-args '["/var/www"]' \
    --task-kwargs '{"quarantine_matches": true}'

Your automation is now handled by the FalconDefender daemon and can be monitored from the TUI.
