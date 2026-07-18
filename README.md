# FGUARD UTC — Update Repository

This repository contains software updates for FGUARD UTC installations.

## How it works

- `version.json` — current release version and changelog
- Source files (same directory structure as `/opt/aegisguard`) — updated when a new version is released

FGUARD UTC installations check this repo **once daily** for new versions.  
If an update is available, it appears in the **Updates** section of the web UI.  
The IT administrator applies the update at their own schedule.

> Updates only apply to licensed FGUARD UTC installations.
