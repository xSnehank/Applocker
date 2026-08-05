# Contributing to Sneh's AppLocker

First off, thanks for taking the time to contribute! 🎉

The following is a set of guidelines for contributing to this project. These are mostly guidelines, not rules — use your best judgment, and feel free to propose changes to this document in a pull request.

## How Can I Contribute?

### 🐛 Reporting Bugs

Before creating a bug report, please check the [Issues](../../issues) page to see if it's already been reported. When you create a bug report, include:

- A clear, descriptive title
- Steps to reproduce the issue
- Expected behavior vs. actual behavior
- Your OS version and Python version
- Screenshots, if applicable
- Any relevant error messages / stack traces

### 💡 Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues too. When creating one, please include:

- A clear, descriptive title
- A detailed description of the proposed feature and why it would be useful
- Any alternative solutions or features you've considered

### 🔧 Pull Requests

1. **Fork** the repository and create your branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. **Set up your environment**:
   ```bash
   pip install -r requirements.txt
   ```
3. **Make your changes.** Please:
   - Keep functions focused and readable
   - Follow existing naming conventions and code style (PEP 8 where reasonable)
   - Add docstrings/comments for non-obvious logic, especially around security-sensitive code (password hashing, process suspension, Windows auth)
   - Avoid introducing new third-party dependencies unless necessary — discuss first in an issue if you think one is needed
4. **Test your changes** locally on Windows before submitting, since core functionality (process suspension, `LogonUserW`) is Windows-specific.
5. **Commit** with clear, descriptive messages:
   ```bash
   git commit -m "Add: brief description of change"
   ```
6. **Push** to your fork and **open a Pull Request** against `main`. Describe:
   - What the change does
   - Why it's needed
   - How you tested it

### 🔒 Security-Sensitive Contributions

This project handles password hashing and process control. If you're proposing changes to:

- Password hashing/storage (`hash_data`, `encode_app_pwd`, `decode_app_pwd`)
- Recovery flows (`RecoveryDialog`, `ResetPasswordsDialog`)
- Process suspension/monitoring (`ProcessMonitorWorker`)
- Windows authentication (`verify_windows_password`)

please explain your reasoning clearly in the PR description, and consider opening an issue first to discuss the approach before investing time in an implementation. If you discover a security vulnerability, please avoid filing a public issue — see below.

### 🚨 Reporting a Vulnerability

If you find a security vulnerability, please **do not open a public issue**. Instead, contact the maintainer directly (see repository owner's GitHub profile for contact details) so it can be addressed before public disclosure.

## Code Style

- Follow [PEP 8](https://peps.python.org/pep-0008/) conventions where practical.
- Prefer descriptive variable/function names over comments explaining unclear ones.
- Keep UI logic (PyQt widgets/dialogs) and core logic (config, hashing, process monitoring) conceptually separated, even within the same file, to ease future refactors into modules.

## Code of Conduct

Be respectful and constructive. Assume good faith. Disagreements about implementation are fine and expected — personal attacks are not.

---

Thanks again for contributing! 🙌
