#!/usr/bin/env python3
"""
===============================================================================
                     Sneh's AppLocker - System Gatekeeper
===============================================================================
A lightweight Windows application guardian built with PyQt6 and psutil. 

Dependencies:
    pip install PyQt6 psutil

How to convert to an executable:
    1. Open your terminal/command prompt.
    2. Run: pip install pyinstaller
    3. Run: pyinstaller --noconsole --onefile --windowed snehs_applocker.py
===============================================================================
"""

import base64
import ctypes
import getpass
import hashlib
import json
import os
import secrets
import string
import sys
import time
from typing import Set

import psutil
from PyQt6.QtCore import QObject, Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

CONFIG_FILE = "snehs_applocker_config.json"

SYSTEM_PROTECTED_APPS = {
    "taskmgr.exe", "explorer.exe", "lsass.exe", "csrss.exe",
    "svchost.exe", "services.exe", "winlogon.exe", "smss.exe",
    "system", "cmd.exe", "powershell.exe", "conhost.exe", "registry",
    "spoolsv.exe", "fontdrvhost.exe", "dwm.exe"
}


# =========================================================================
# Security & Helper Utilities
# =========================================================================

def hash_data(data: str) -> str:
    """Creates a secure one-way hash for Master and Startup passwords."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()

def encode_app_pwd(pwd: str) -> str:
    """Reversibly obfuscates app-specific passwords to keep them out of plain text in JSON."""
    if not pwd: return ""
    return base64.b64encode(pwd.encode('utf-8')).decode('utf-8')

def decode_app_pwd(encoded: str) -> str:
    """Decodes obfuscated app-specific passwords so the user can view them."""
    if not encoded: return ""
    try:
        return base64.b64decode(encoded.encode('utf-8')).decode('utf-8')
    except Exception:
        return ""

def generate_recovery_key() -> str:
    """Generates a secure 16-character recovery key grouped by hyphens."""
    chars = string.ascii_uppercase + string.digits
    raw_key = ''.join(secrets.choice(chars) for _ in range(16))
    return f"SNEH-{raw_key[:4]}-{raw_key[4:8]}-{raw_key[8:12]}-{raw_key[12:]}"

def verify_windows_password(password: str) -> bool:
    """Verifies the local Windows user password using native Win32 APIs."""
    if sys.platform != "win32":
        return True # Fallback if run on Linux/Mac
        
    try:
        from ctypes import wintypes
        username = getpass.getuser()
        advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
        
        advapi32.LogonUserW.argtypes = [
            wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
            wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)
        ]
        advapi32.LogonUserW.restype = wintypes.BOOL
        
        token = wintypes.HANDLE()
        # LOGON32_LOGON_INTERACTIVE = 2, LOGON32_PROVIDER_DEFAULT = 0
        result = advapi32.LogonUserW(username, None, password, 2, 0, ctypes.byref(token))
        
        if result:
            ctypes.windll.kernel32.CloseHandle(token)
            return True
        return False
    except Exception:
        return False

def load_config() -> dict:
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as file:
                data = json.load(file)
                if isinstance(data, dict):
                    data.setdefault("startup_hash", "")
                    data.setdefault("master_hash", "")
                    data.setdefault("recovery_hash", "")
                    data.setdefault("locked_apps", [])
                    data.setdefault("app_passwords", {}) # New mapping for app-specific passwords
                    data.setdefault("enabled", True)
                    return data
        except (json.JSONDecodeError, OSError):
            pass
    return {"startup_hash": "", "master_hash": "", "recovery_hash": "", "locked_apps": [], "app_passwords": {}, "enabled": True}

def save_config(config: dict) -> None:
    with open(CONFIG_FILE, "w", encoding="utf-8") as file:
        json.dump(config, file, indent=4)

def get_current_app_name() -> str:
    if getattr(sys, 'frozen', False):
        return os.path.basename(sys.executable).lower()
    return os.path.basename(sys.argv[0]).lower()


# =========================================================================
# Setup & Recovery Modals
# =========================================================================

class InitialSetupDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Welcome to Sneh's AppLocker - Initial Setup")
        self.setMinimumSize(450, 400)

        layout = QVBoxLayout()
        layout.addWidget(QLabel("<b>Secure Your Application</b><br>Please set up your dual-password system."))

        layout.addWidget(QLabel("<b>1. Startup Password</b> (Used to open this AppLocker console):"))
        self.startup_pwd = QLineEdit()
        self.startup_pwd.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.startup_pwd)

        layout.addWidget(QLabel("<b>2. Master Password</b> (Used to unlock your protected apps):"))
        self.master_pwd = QLineEdit()
        self.master_pwd.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.master_pwd)

        self.recovery_key = generate_recovery_key()
        layout.addWidget(QLabel("<br><b>3. Master Recovery Key</b> (Save this somewhere safe!):"))
        
        key_display = QTextEdit()
        key_display.setText(self.recovery_key)
        key_display.setReadOnly(True)
        key_display.setMaximumHeight(60)
        key_display.setStyleSheet("font-family: monospace; font-size: 14pt; font-weight: bold;")
        layout.addWidget(key_display)

        layout.addWidget(QLabel("<i>If you forget your passwords, you will need this key or your Windows PC password to reset them.</i>"))

        save_btn = QPushButton("Save & Initialize")
        save_btn.clicked.connect(self.save_setup)
        layout.addWidget(save_btn)

        self.setLayout(layout)

    def showEvent(self, event):
        super().showEvent(event)
        screen = self.screen()
        if screen:
            self.move(screen.availableGeometry().center() - self.frameGeometry().center())

    def save_setup(self):
        s_pwd = self.startup_pwd.text().strip()
        m_pwd = self.master_pwd.text().strip()

        if not s_pwd or not m_pwd:
            QMessageBox.warning(self, "Error", "Both passwords must be provided.")
            return

        config = load_config()
        config["startup_hash"] = hash_data(s_pwd)
        config["master_hash"] = hash_data(m_pwd)
        config["recovery_hash"] = hash_data(self.recovery_key)
        save_config(config)

        QMessageBox.information(self, "Setup Complete", "AppLocker secured successfully!")
        self.accept()


class RecoveryDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Account Recovery")
        self.setMinimumSize(400, 250)

        self.setWindowFlags(Qt.WindowType.Window | Qt.WindowType.WindowStaysOnTopHint | Qt.WindowType.WindowTitleHint)

        layout = QVBoxLayout()
        layout.addWidget(QLabel("Choose a method to verify your identity:"))

        tabs = QTabWidget()

        # Method 1: Recovery Key
        key_tab = QWidget()
        key_layout = QVBoxLayout()
        key_layout.addWidget(QLabel("Enter your 16-character Master Recovery Key:"))
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("SNEH-XXXX-XXXX-XXXX-XXXX")
        key_layout.addWidget(self.key_input)
        
        key_btn = QPushButton("Verify Key")
        key_btn.clicked.connect(self.verify_recovery_key)
        key_layout.addWidget(key_btn)
        key_tab.setLayout(key_layout)

        # Method 2: Windows Password
        os_tab = QWidget()
        os_layout = QVBoxLayout()
        os_layout.addWidget(QLabel("Verify using your local Windows Administrator Password:"))
        self.os_input = QLineEdit()
        self.os_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.os_input.setPlaceholderText("Your PC login password")
        os_layout.addWidget(self.os_input)
        
        os_btn = QPushButton("Verify OS Password")
        os_btn.clicked.connect(self.verify_os_password)
        os_layout.addWidget(os_btn)
        os_tab.setLayout(os_layout)

        tabs.addTab(key_tab, "Option 1: Recovery Key")
        tabs.addTab(os_tab, "Option 2: Windows Password")

        layout.addWidget(tabs)
        self.setLayout(layout)
        self.config = load_config()

    def showEvent(self, event):
        super().showEvent(event)
        screen = self.screen()
        if screen:
            self.move(screen.availableGeometry().center() - self.frameGeometry().center())

    def verify_recovery_key(self):
        user_key = self.key_input.text().strip().upper()
        if hash_data(user_key) == self.config.get("recovery_hash"):
            self.accept()
        else:
            QMessageBox.critical(self, "Access Denied", "Invalid Recovery Key.")

    def verify_os_password(self):
        user_os_pwd = self.os_input.text()
        if not user_os_pwd:
            QMessageBox.warning(self, "Error", "Windows password cannot be empty.")
            return

        if verify_windows_password(user_os_pwd):
            self.accept()
        else:
            QMessageBox.critical(self, "Access Denied", "Incorrect Windows Password.")
            self.os_input.clear()


class ResetPasswordsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Set New Passwords")
        self.setMinimumSize(360, 200)

        self.setWindowFlags(Qt.WindowType.Window | Qt.WindowType.WindowStaysOnTopHint | Qt.WindowType.WindowTitleHint)

        layout = QVBoxLayout()
        layout.addWidget(QLabel("Identity verified. You may now reset your passwords."))

        layout.addWidget(QLabel("New Startup Password (Optional - leave blank to keep current):"))
        self.startup_pwd = QLineEdit()
        self.startup_pwd.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.startup_pwd)

        layout.addWidget(QLabel("New Master Password (Optional - leave blank to keep current):"))
        self.master_pwd = QLineEdit()
        self.master_pwd.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.master_pwd)

        save_btn = QPushButton("Update Credentials")
        save_btn.clicked.connect(self.save_new_passwords)
        layout.addWidget(save_btn)

        self.setLayout(layout)

    def showEvent(self, event):
        super().showEvent(event)
        screen = self.screen()
        if screen:
            self.move(screen.availableGeometry().center() - self.frameGeometry().center())

    def save_new_passwords(self):
        s_pwd = self.startup_pwd.text().strip()
        m_pwd = self.master_pwd.text().strip()

        if not s_pwd and not m_pwd:
            QMessageBox.information(self, "Info", "No passwords were changed.")
            self.reject()
            return

        config = load_config()
        if s_pwd:
            config["startup_hash"] = hash_data(s_pwd)
        if m_pwd:
            config["master_hash"] = hash_data(m_pwd)
            
        save_config(config)
        QMessageBox.information(self, "Success", "Passwords updated successfully!")
        self.accept()


class StartupLoginDialog(QDialog):
    def __init__(self, startup_hash: str, parent=None):
        super().__init__(parent)
        self.startup_hash = startup_hash
        self.setWindowTitle("AppLocker Console Login")
        self.setMinimumSize(320, 160)

        layout = QVBoxLayout()
        layout.addWidget(QLabel("Enter <b>Startup Password</b> to access the console:"))

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.password_input)

        btn_layout = QHBoxLayout()
        login_btn = QPushButton("Login")
        login_btn.setDefault(True)
        login_btn.clicked.connect(self.verify_login)

        forgot_btn = QPushButton("Forgot Password?")
        forgot_btn.clicked.connect(self.handle_forgot_password)

        btn_layout.addWidget(login_btn)
        btn_layout.addWidget(forgot_btn)
        layout.addLayout(btn_layout)

        self.setLayout(layout)

    def showEvent(self, event):
        super().showEvent(event)
        screen = self.screen()
        if screen:
            self.move(screen.availableGeometry().center() - self.frameGeometry().center())

    def verify_login(self):
        user_input = self.password_input.text()
        if hash_data(user_input) == self.startup_hash:
            self.accept()
        else:
            QMessageBox.critical(self, "Access Denied", "Incorrect Startup Password.")
            self.password_input.clear()

    def handle_forgot_password(self):
        recovery = RecoveryDialog(self)
        if recovery.exec() == QDialog.DialogCode.Accepted:
            reset = ResetPasswordsDialog(self)
            if reset.exec() == QDialog.DialogCode.Accepted:
                self.startup_hash = load_config().get("startup_hash")
                self.password_input.clear()
                QMessageBox.information(self, "Success", "Please login with your new Startup Password.")


class MasterAuthDialog(QDialog):
    """Requires the Master Password before allowing user to view/change App Specific passwords."""
    def __init__(self, master_hash: str, parent=None):
        super().__init__(parent)
        self.master_hash = master_hash
        self.setWindowTitle("Master Authentication Required")
        self.setMinimumSize(320, 120)

        layout = QVBoxLayout()
        layout.addWidget(QLabel("Please enter your <b>Master Password</b> to continue:"))

        self.pwd_input = QLineEdit()
        self.pwd_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.pwd_input)

        btn = QPushButton("Verify Identity")
        btn.setDefault(True)
        btn.clicked.connect(self.verify)
        layout.addWidget(btn)

        self.setLayout(layout)

    def showEvent(self, event):
        super().showEvent(event)
        screen = self.screen()
        if screen:
            self.move(screen.availableGeometry().center() - self.frameGeometry().center())

    def verify(self):
        if hash_data(self.pwd_input.text()) == self.master_hash:
            self.accept()
        else:
            QMessageBox.warning(self, "Access Denied", "Incorrect Master Password.")
            self.pwd_input.clear()


class AppPasswordDialog(QDialog):
    """Dialog to display and change an app-specific password."""
    def __init__(self, app_name: str, current_pwd: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"App Password: {app_name}")
        self.setMinimumSize(320, 180)

        layout = QVBoxLayout()

        layout.addWidget(QLabel(f"<b>Current App Password for {app_name}:</b>"))
        self.current_display = QLineEdit()
        self.current_display.setText(current_pwd if current_pwd else "None Set")
        self.current_display.setReadOnly(True)
        self.current_display.setStyleSheet("background-color: #f0f0f0; color: #333;")
        layout.addWidget(self.current_display)

        layout.addWidget(QLabel("<b>Set New App Password:</b><br><i>(Leave completely blank to clear and use Master only)</i>"))
        self.new_input = QLineEdit()
        layout.addWidget(self.new_input)

        save_btn = QPushButton("Save & Update")
        save_btn.setDefault(True)
        save_btn.clicked.connect(self.accept)
        layout.addWidget(save_btn)

        self.setLayout(layout)

    def get_password(self):
        return self.new_input.text().strip()


class UnlockDialog(QDialog):
    def __init__(self, app_name: str, stored_master_hash: str, plain_app_pwd: str, parent=None):
        super().__init__(parent)
        self.stored_master_hash = stored_master_hash
        self.plain_app_pwd = plain_app_pwd
        self.authenticated = False
        self.app_name = app_name

        self.setWindowTitle("Sneh's AppLocker - Security Check")
        self.setMinimumSize(380, 190)

        # Enforce independent pop-out window
        self.setWindowFlags(Qt.WindowType.Window | Qt.WindowType.WindowStaysOnTopHint | Qt.WindowType.WindowTitleHint)

        layout = QVBoxLayout()
        
        prompt_text = "Enter App Password or Master Password to unlock:" if plain_app_pwd else "Enter Master Password to unlock execution:"
        
        info_label = QLabel(
            f"<b>'{app_name}'</b> is locked by Sneh's AppLocker.<br><br>"
            f"{prompt_text}"
        )
        info_label.setWordWrap(True)
        layout.addWidget(info_label)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Password")
        layout.addWidget(self.password_input)

        btn_layout = QHBoxLayout()
        unlock_btn = QPushButton("Unlock")
        unlock_btn.setDefault(True)
        unlock_btn.clicked.connect(self.verify_credentials)

        term_btn = QPushButton("Terminate App")
        term_btn.clicked.connect(self.confirm_and_reject)
        
        btn_layout.addWidget(unlock_btn)
        btn_layout.addWidget(term_btn)
        layout.addLayout(btn_layout)

        forgot_btn = QPushButton("Forgot Password?")
        forgot_btn.clicked.connect(self.handle_forgot_password)
        layout.addWidget(forgot_btn)

        self.setLayout(layout)

    def showEvent(self, event):
        super().showEvent(event)
        screen = self.screen()
        if screen:
            self.move(screen.availableGeometry().center() - self.frameGeometry().center())

    def verify_credentials(self):
        user_input = self.password_input.text()
        
        # Check if the user input matches either the Master Hash OR the plain App Password
        if hash_data(user_input) == self.stored_master_hash or (self.plain_app_pwd and user_input == self.plain_app_pwd):
            self.authenticated = True
            self.accept()
        else:
            QMessageBox.critical(self, "Access Denied", "Incorrect Password. Try again.")
            self.password_input.clear()

    def confirm_and_reject(self):
        confirm = QMessageBox.question(
            self, "Confirm Termination", f"Forcibly terminate '{self.app_name}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if confirm == QMessageBox.StandardButton.Yes:
            self.reject()

    def handle_forgot_password(self):
        recovery = RecoveryDialog(self) 
        if recovery.exec() == QDialog.DialogCode.Accepted:
            reset = ResetPasswordsDialog(self)
            if reset.exec() == QDialog.DialogCode.Accepted:
                # Reload updated hash to allow immediate unlocking
                self.stored_master_hash = load_config().get("master_hash")
                self.password_input.clear()
                QMessageBox.information(self, "Success", "Please unlock the application with your new Master Password.")


# =========================================================================
# Asynchronous Watchdog Engine
# =========================================================================

class MonitorSignals(QObject):
    prompt_unlock = pyqtSignal(int, str)

class ProcessMonitorWorker(QThread):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.signals = MonitorSignals()
        self.running = True
        self.unlocked_pids: Set[int] = set()
        self.pending_pids: Set[int] = set()

    def run(self):
        while self.running:
            config = self.main_window.config

            if config.get("enabled", True) and config.get("locked_apps"):
                locked_targets = {app.lower() for app in config["locked_apps"]}

                active_pids = set(psutil.pids())
                self.unlocked_pids.intersection_update(active_pids)
                self.pending_pids.intersection_update(active_pids)

                for proc in psutil.process_iter(["pid", "name"]):
                    try:
                        pid = proc.info["pid"]
                        proc_name = proc.info["name"] or ""
                        clean_name = proc_name.lower()

                        if (
                            clean_name in locked_targets 
                            and pid not in self.unlocked_pids
                            and pid not in self.pending_pids
                            and clean_name not in SYSTEM_PROTECTED_APPS
                            and clean_name != get_current_app_name()
                        ):
                            try:
                                target_proc = psutil.Process(pid)
                                target_proc.suspend()
                            except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
                                pass

                            self.pending_pids.add(pid)
                            self.signals.prompt_unlock.emit(pid, proc_name)

                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue

            time.sleep(0.5)

    def mark_unlocked(self, pid: int):
        self.unlocked_pids.add(pid)
        self.pending_pids.discard(pid)

    def remove_pending(self, pid: int):
        self.pending_pids.discard(pid)

    def stop(self):
        self.running = False
        self.wait()


# =========================================================================
# Main Dashboard Console
# =========================================================================

class SnehAppLockerWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.config = load_config()
        self.setWindowTitle("Sneh's AppLocker Security Console")
        self.resize(680, 540)

        self.setup_ui()

        self.monitor_thread = ProcessMonitorWorker(self)
        self.monitor_thread.signals.prompt_unlock.connect(self.handle_unlock_request)
        self.monitor_thread.start()

    def setup_ui(self):
        central_widget = QWidget()
        main_layout = QVBoxLayout()

        status_box = QGroupBox("Protection Control")
        status_layout = QHBoxLayout()

        self.status_label = QLabel()
        self.sync_status_label()

        self.toggle_btn = QPushButton()
        self.sync_toggle_button()
        self.toggle_btn.clicked.connect(self.toggle_global_protection)

        change_pass_btn = QPushButton("Manage Main Passwords")
        change_pass_btn.clicked.connect(self.action_manage_passwords)

        status_layout.addWidget(self.status_label)
        status_layout.addStretch()
        status_layout.addWidget(self.toggle_btn)
        status_layout.addWidget(change_pass_btn)
        status_box.setLayout(status_layout)
        main_layout.addWidget(status_box)

        tabs = QTabWidget()

        # Tab 1: Locked Apps 
        locked_tab = QWidget()
        locked_layout = QVBoxLayout()

        self.locked_list_widget = QListWidget()
        self.refresh_locked_list_view()

        action_row = QHBoxLayout()
        add_manual_btn = QPushButton("+ Add App")
        add_manual_btn.clicked.connect(self.add_manual_app_dialog)

        manage_app_pwd_btn = QPushButton("View/Change App Password")
        manage_app_pwd_btn.clicked.connect(self.manage_app_password)

        remove_btn = QPushButton("- Remove Selected")
        remove_btn.clicked.connect(self.remove_selected_app)

        action_row.addWidget(add_manual_btn)
        action_row.addWidget(manage_app_pwd_btn)
        action_row.addWidget(remove_btn)

        locked_layout.addWidget(QLabel("Locked executables requiring authentication:"))
        locked_layout.addWidget(self.locked_list_widget)
        locked_layout.addLayout(action_row)
        locked_tab.setLayout(locked_layout)

        # Tab 2: Running Processes
        running_tab = QWidget()
        running_layout = QVBoxLayout()

        self.proc_table = QTableWidget()
        self.proc_table.setColumnCount(2)
        self.proc_table.setHorizontalHeaderLabels(["Process Name", "PID"])
        self.proc_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.proc_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.proc_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)

        refresh_table_btn = QPushButton("Refresh Running Processes")
        refresh_table_btn.clicked.connect(self.refresh_running_processes)

        lock_proc_btn = QPushButton("Lock Selected Application")
        lock_proc_btn.clicked.connect(self.lock_selected_process)

        running_layout.addWidget(self.proc_table)
        running_layout.addWidget(refresh_table_btn)
        running_layout.addWidget(lock_proc_btn)
        running_tab.setLayout(running_layout)

        tabs.addTab(locked_tab, "Locked Apps")
        tabs.addTab(running_tab, "Active System Processes")

        main_layout.addWidget(tabs)
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)
        self.refresh_running_processes()

    def sync_status_label(self):
        is_active = self.config.get("enabled", True)
        state_text = "ACTIVE" if is_active else "DISABLED"
        color = "#27ae60" if is_active else "#e74c3c"
        self.status_label.setText(f"System Protection: <font color='{color}'><b>{state_text}</b></font>")

    def sync_toggle_button(self):
        is_active = self.config.get("enabled", True)
        self.toggle_btn.setText("Disable Protection" if is_active else "Enable Protection")

    def toggle_global_protection(self):
        self.config["enabled"] = not self.config.get("enabled", True)
        save_config(self.config)
        self.sync_status_label()
        self.sync_toggle_button()

    def action_manage_passwords(self):
        recovery = RecoveryDialog(self)
        if recovery.exec() == QDialog.DialogCode.Accepted:
            reset = ResetPasswordsDialog(self)
            if reset.exec() == QDialog.DialogCode.Accepted:
                self.config = load_config()

    def refresh_locked_list_view(self):
        self.locked_list_widget.clear()
        for app_name in self.config.get("locked_apps", []):
            has_pwd = app_name in self.config.get("app_passwords", {})
            display_text = f"{app_name} (Custom Password Set)" if has_pwd else app_name
            self.locked_list_widget.addItem(display_text)

    def is_safe_to_lock(self, target_name: str) -> bool:
        clean = target_name.lower().strip()
        if clean == get_current_app_name():
            QMessageBox.warning(self, "Action Denied", "Sneh's AppLocker cannot lock itself.")
            return False
        if clean in SYSTEM_PROTECTED_APPS:
            QMessageBox.warning(self, "Action Denied", f"'{clean}' is a critical system app and cannot be locked.")
            return False
        return True

    def add_manual_app_dialog(self):
        self.manual_dialog = QDialog(self)
        self.manual_dialog.setWindowTitle("Add Executable to Locklist")
        self.manual_dialog.setMinimumSize(320, 130)

        layout = QVBoxLayout()
        layout.addWidget(QLabel("Executable filename (e.g., chrome.exe):"))

        input_field = QLineEdit()
        input_field.setPlaceholderText("e.g., notepad.exe")
        layout.addWidget(input_field)

        submit_btn = QPushButton("Add Application")
        layout.addWidget(submit_btn)
        self.manual_dialog.setLayout(layout)

        self.manual_dialog.showEvent = lambda event: self.manual_dialog.move(
            self.manual_dialog.screen().availableGeometry().center() - self.manual_dialog.frameGeometry().center()
        )

        def submit():
            target_name = input_field.text().strip().lower()
            if target_name:
                if not target_name.endswith(".exe"):
                    target_name += ".exe"

                if self.is_safe_to_lock(target_name):
                    if target_name not in self.config["locked_apps"]:
                        self.config["locked_apps"].append(target_name)
                        save_config(self.config)
                        self.refresh_locked_list_view()
                    self.manual_dialog.accept()

        submit_btn.clicked.connect(submit)
        self.manual_dialog.exec()

    def manage_app_password(self):
        selected_item = self.locked_list_widget.currentItem()
        if not selected_item:
            QMessageBox.warning(self, "Selection Required", "Please select an app from the list first.")
            return
            
        # The list item text might contain " (Custom Password Set)", we must strip it to get the raw app name
        app_name = selected_item.text().replace(" (Custom Password Set)", "")

        # 1. Ask for Master Password first to authorize view/change
        auth_dialog = MasterAuthDialog(self.config["master_hash"], self)
        if auth_dialog.exec() == QDialog.DialogCode.Accepted:
            
            # 2. Decode current app password and display App Password Manager
            encoded_pwd = self.config.get("app_passwords", {}).get(app_name, "")
            current_pwd = decode_app_pwd(encoded_pwd)

            app_pwd_dialog = AppPasswordDialog(app_name, current_pwd, self)
            if app_pwd_dialog.exec() == QDialog.DialogCode.Accepted:
                new_pwd = app_pwd_dialog.get_password()
                
                # Make sure dict exists
                if "app_passwords" not in self.config:
                    self.config["app_passwords"] = {}
                
                if new_pwd:
                    self.config["app_passwords"][app_name] = encode_app_pwd(new_pwd)
                else:
                    self.config["app_passwords"].pop(app_name, None)
                
                save_config(self.config)
                self.refresh_locked_list_view() # Refresh UI string to show/hide "Custom Password Set" text
                QMessageBox.information(self, "Success", f"Password settings updated for {app_name}.")

    def remove_selected_app(self):
        selected_item = self.locked_list_widget.currentItem()
        if selected_item:
            app_name = selected_item.text().replace(" (Custom Password Set)", "")
            self.config["locked_apps"].remove(app_name)
            
            # Clean up the password reference
            if "app_passwords" in self.config and app_name in self.config["app_passwords"]:
                del self.config["app_passwords"][app_name]
                
            save_config(self.config)
            self.refresh_locked_list_view()

    def refresh_running_processes(self):
        self.proc_table.setRowCount(0)
        discovered_apps = {}
        ignored_keywords = [
            ".tmp", "crdownload", "part", "installer", 
            "setup", "update", "downloader", "upload", "crashpad", "telemetry"
        ]

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pname = proc.info["name"]
                if pname and pname.lower().endswith(".exe"):
                    clean = pname.lower()

                    if any(kw in clean for kw in ignored_keywords):
                        continue
                    if clean == get_current_app_name() or clean in SYSTEM_PROTECTED_APPS:
                        continue

                    discovered_apps[pname] = proc.info["pid"]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        for row, (name, pid) in enumerate(sorted(discovered_apps.items())):
            self.proc_table.insertRow(row)
            self.proc_table.setItem(row, 0, QTableWidgetItem(name))
            self.proc_table.setItem(row, 1, QTableWidgetItem(str(pid)))

    def lock_selected_process(self):
        selected_items = self.proc_table.selectedItems()
        if selected_items:
            target_row = selected_items[0].row()
            proc_name = self.proc_table.item(target_row, 0).text().lower()

            if self.is_safe_to_lock(proc_name):
                if proc_name not in self.config["locked_apps"]:
                    self.config["locked_apps"].append(proc_name)
                    save_config(self.config)
                    self.refresh_locked_list_view()
                    QMessageBox.information(
                        self, "Success", f"'{proc_name}' added to Sneh's AppLocker target list."
                    )

    def handle_unlock_request(self, pid: int, app_name: str):
        # Fetch decoded specific app password, if any
        encoded_app_pwd = self.config.get("app_passwords", {}).get(app_name.lower(), "")
        plain_app_pwd = decode_app_pwd(encoded_app_pwd)

        dialog = UnlockDialog(app_name, self.config["master_hash"], plain_app_pwd, None)
        dialog.exec()

        try:
            target_process = psutil.Process(pid)
            if dialog.authenticated:
                try:
                    target_process.resume()
                    self.monitor_thread.mark_unlocked(pid)
                except (psutil.AccessDenied, AttributeError):
                    pass
            else:
                target_process.kill()
        except psutil.NoSuchProcess:
            pass

        self.monitor_thread.remove_pending(pid)

    def closeEvent(self, event):
        self.monitor_thread.stop()
        event.accept()


# =========================================================================
# Application Entry Point
# =========================================================================

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    config = load_config()
    
    if not config.get("startup_hash") or not config.get("master_hash") or not config.get("recovery_hash"):
        setup_dialog = InitialSetupDialog()
        if setup_dialog.exec() != QDialog.DialogCode.Accepted:
            sys.exit(0)
        config = load_config()

    login = StartupLoginDialog(config["startup_hash"])
    if login.exec() != QDialog.DialogCode.Accepted:
        sys.exit(0)

    main_window = SnehAppLockerWindow()
    main_window.show()

    sys.exit(app.exec())