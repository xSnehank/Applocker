# Sneh's AppLocker 

A lightweight Windows desktop utility that lets you **password-protect individual applications**. When a locked app is launched, it's automatically suspended and a prompt asks for a password before allowing it to run — or terminating it if authentication fails.

Built with **Python** and **PyQt6**.

---

##  Features

- **Global App Lock** — Choose any running or manually-specified `.exe` and require a password before it can be used.
- **Dual-Password System**
  - **Startup Password** — required to open the AppLocker console itself.
  - **Master Password** — required to unlock any locked application.
- **Per-App Passwords (optional)** — Set an app-specific password as an alternative to the master password for a given executable.
- **Account Recovery** — Reset your passwords using either:
  - A generated **16-character Recovery Key** (shown once at setup — save it!), or
  - Your local **Windows account password**.
- **Live Process Monitoring** — A background watchdog thread checks running processes and suspends locked apps the moment they launch.
- **System Safety Guards** — Critical system processes (`explorer.exe`, `lsass.exe`, `winlogon.exe`, etc.) and the AppLocker app itself can never be locked.
- **Toggle Protection** — Enable/disable enforcement globally without losing your locked-app list.
- **Simple Qt-based UI** with tabs for locked apps and live system processes.

---

##  Requirements

- Windows 10/11 (uses native Win32 APIs for Windows-password verification; falls back gracefully on other platforms)
- Python 3.10+
- Dependencies:
  ```
  PyQt6
  psutil
  ```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

##  Running from Source

```bash
git clone https://github.com/xSnehank/Applocker.git
cd Applocker
pip install -r requirements.txt
python main.py
```

On first launch you'll be guided through **Initial Setup**, where you'll create:
1. A Startup Password
2. A Master Password
3. A Recovery Key (shown once — store it somewhere safe, e.g. a password manager)

---

##  Building the Executable

This project is packaged with [PyInstaller](https://pyinstaller.org/).

```bash
pip install pyinstaller
pyinstaller --onefile --noconsole --name applocker.py
```

The compiled binary will be available in `dist/SnehAppLocker.exe`.

> **Note:** Pre-built executables are also available on the [Releases](../../releases) page of this repository, if you'd rather not build from source.

---

##  Security Notes

- Passwords are stored as **SHA-256 hashes** (`hash_data()`), never in plain text.
- App-specific passwords are stored **base64-obfuscated** (`encode_app_pwd()` / `decode_app_pwd()`) rather than encrypted — this is a light deterrent, not cryptographic protection. Anyone with local access to `snehs_applocker_config.json` and knowledge of the format could decode them. Treat this as convenience obfuscation, not a secrets vault.
- This tool relies on process suspension via `psutil`, which requires appropriate OS permissions and can be bypassed by a sufficiently privileged user (e.g. via Task Manager "End Task" before the prompt registers, or by running as an administrator). It is intended as a lightweight personal-use deterrent (e.g. for shared family computers), **not** as an enterprise-grade access control or parental-control solution.
- The local config file (`snehs_applocker_config.json`) is excluded from version control via `.gitignore` since it contains your password hashes and obfuscated app passwords — do not commit your personal copy.

---

##  Project Structure

```
.
├── main.py                       # Application entry point (all logic currently in one file)
├── requirements.txt
├── snehs_applocker_config.json   # Generated at runtime — gitignored
├── .gitignore
├── README.md
├── CONTRIBUTING.md
└── LICENSE
```

---

##  Contributing

Contributions, bug reports, and feature suggestions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

##  License

This project is licensed under the terms of the [MIT License](LICENSE).

---

## 🙋 Author

**Sneh** — feel free to open an issue for questions, bugs, or feature requests.
