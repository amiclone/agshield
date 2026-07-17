# Building AntiGravity Shield Executables

This directory contains PyInstaller spec files and build scripts for creating standalone executables.

## Linux Build

```bash
cd antigravity-shield
bash build_scripts/build_linux.sh
```

Output: `dist/agshield` (Linux ELF executable, ~21MB)

### Install on system:
```bash
sudo bash build_scripts/install_linux.sh
```

This installs:
- `/usr/local/bin/agshield` — the executable
- `/usr/local/share/agshield/agent_package/` — bundled agent scripts
- `/etc/antigravity/config.yaml` — default config

## Windows Build

Open a terminal on Windows and run:
```cmd
cd antigravity-shield
build_scripts\build_windows.bat
```

Output: `dist\agshield.exe` (standalone Windows executable)

### Install on system:
```cmd
build_scripts\install_windows.bat
```

This installs:
- `C:\Program Files\antigravity-shield\agshield.exe`
- `C:\Program Files\antigravity-shield\agent_package\`
- Adds to system PATH

## Build from Source (any platform)

If you don't want to use the pre-built scripts:

```bash
# Linux
pyinstaller build_scripts/agshield_linux.spec --clean --noconfirm

# Windows
pyinstaller build_scripts\agshield_windows.spec --clean --noconfirm
```

## What gets bundled

The executable bundles:
- All agshield Python modules
- Python interpreter
- Default YAML config
- Agent scripts (agent_package) for test mode
- Required dependencies: watchdog, psutil, pyyaml, rich, click

## Cross-compilation notes

PyInstaller cannot cross-compile. To build for Windows, you must run the build on Windows. Options:
1. Run the build script directly on a Windows VM
2. Use a Windows CI/CD runner (GitHub Actions, Azure Pipelines)
3. Use Wine on Linux (experimental)

## Standalone executable usage

After installation, the executable works on any system WITHOUT requiring Python:

```bash
# Linux
agshield --version
agshield start --watch /home --watch /tmp
agshield test --stealth-trials 30

# Windows
agshield.exe --version
agshield.exe start --watch C:\Users
agshield.exe test --stealth-trials 30
```

## Uninstall

```bash
# Linux
sudo rm /usr/local/bin/agshield /usr/local/bin/antigravity
sudo rm -rf /usr/local/share/antigravity
sudo rm -f /etc/antigravity/config.yaml

# Windows
# Remove "C:\Program Files\antigravity-shield" directory
# Remove from PATH manually
```

## File sizes

- Linux executable: ~21MB (includes Python interpreter + dependencies)
- Windows executable: ~25MB
- Both include the bundled agent_package for test mode
