# Local Python Environment Execution Diagnosis

**Date:** 4 November 2026  
**Scope:** interpreter startup and read-only environment inspection. No ChainGuard application workflow, test suite, research experiment, database operation, dependency installation, Git command, or repair was run.

## Finding

The `.venv` is valid under the normal Windows account `DESKTOP-U5N1QJS\Laptop`. The audit-time failure occurs because the restricted `DESKTOP-U5N1QJS\codexsandboxoffline` process can access the virtual-environment launcher in the project directory but cannot access the **base Python installation** at `C:\Users\Laptop\AppData\Local\Python\pythoncore-3.14-64`. The base directory and `python.exe` ACLs grant access to `Laptop`, `SYSTEM`, and `Administrators`, but not to `CodexSandboxUsers` or the sandbox account. Direct base-interpreter execution and ACL inspection from the sandbox return `Access is denied`; both base and `.venv` interpreters start successfully as `Laptop`. This is an account/access-boundary issue, not a broken or missing Python binary, missing dependency, or proven OneDrive problem.

**Smallest repair:** run the professor demonstration from an ordinary PowerShell session as the `Laptop` account with the existing `.venv\Scripts\python.exe` path. No `.venv` rebuild, file move, ACL change, or dependency installation is needed for that account. If the demonstration must be run inside the restricted Codex sandbox, its inability to traverse the private base Python installation must be addressed separately by an approved, narrowly scoped environment/access arrangement. Do not broaden ACLs or copy the private interpreter merely to make this sandbox run it.

## Structure, interpreter path, and declarations

The environment has `Include/`, `Lib/`, `Scripts/`, `pyvenv.cfg`, and `.gitignore`. `Scripts/` contains `python.exe` (255,320 bytes), `pythonw.exe`, `Activate.ps1`, `activate.bat`, POSIX/fish activation scripts, `pip*.exe`, and installed-package console launchers. No extensionless `Scripts/python` launcher was found on this Windows environment. The activation scripts set `VIRTUAL_ENV` and prepend `Scripts` to `PATH`; direct invocation does not require activation. `Get-ExecutionPolicy -List` showed `LocalMachine=RemoteSigned` and all higher scopes undefined. The failure reproduces with direct `python.exe`, so a PowerShell script-execution policy is not its cause.

`pyvenv.cfg` records:

```text
home = C:\Users\Laptop\AppData\Local\Python\pythoncore-3.14-64
include-system-site-packages = false
version = 3.14.3
executable = C:\Users\Laptop\AppData\Local\Python\pythoncore-3.14-64\python.exe
```

The base `python.exe` and `python314.dll` both exist at that location. The `.venv` launcher reports file version 3.14.3 and original filename `py.exe`; its Authenticode signature status was `Valid`. Neither launcher had a `Zone.Identifier` alternate stream in the successful normal-account stream inspection. The project declares 29 exact package pins in `requirements-m1.txt`; no separate root lock file or `pyproject.toml` was found. A read-only `importlib.metadata` check under the normal account found all 29 installed versions matching their pins, including `mcp==2.3.0` and `cryptography==50.0.2`. This checks installed metadata, not a clean installation or application behavior.

## Exact reproduction and comparison

Commands below ran from `C:\Users\Laptop\OneDrive\Documents\MIT\ChainGuard`. `exec_command` itself returned 0 for the PowerShell diagnostic block when the block only printed failures; the meaningful child `LASTEXITCODE` is shown separately. The prior audit's M1/M2 invocations failed at the same launcher boundary before importing ChainGuard.

| Account / command | Observed output | Child result |
| --- | --- | --- |
| Sandbox: `& '.\.venv\Scripts\python.exe' --version` | `Unable to create process using '"C:\Users\Laptop\OneDrive\Documents\MIT\ChainGuard\.venv\Scripts\python.exe" --version': Access is denied.` | `LASTEXITCODE=101`; no Python version printed. |
| Sandbox, documented interpreter flags: `& '.\.venv\Scripts\python.exe' -B --version` | Same launcher `Access is denied` message. | `LASTEXITCODE=101`; no Python startup. |
| Sandbox: `& 'C:\Users\Laptop\AppData\Local\Python\pythoncore-3.14-64\python.exe' --version` | PowerShell `ResourceUnavailable`: program failed to start, `Access is denied`. | No base-Python child exit code: process creation failed. The block printed a stale `LASTEXITCODE=101` from the preceding `.venv` attempt. |
| Normal `Laptop` account: `& '.\.venv\Scripts\python.exe' --version` | `Python 3.14.3` | `LASTEXITCODE=0`. |
| Normal `Laptop` account: `& 'C:\Users\Laptop\AppData\Local\Python\pythoncore-3.14-64\python.exe' --version` | `Python 3.14.3` | `LASTEXITCODE=0`. |
| Normal `Laptop` account: `& '.\.venv\Scripts\python.exe' -B -c 'import sys; print(sys.executable); print(sys._base_executable)'` | Virtual path, then `C:\Users\Laptop\AppData\Local\Python\pythoncore-3.14-64\python.exe`. | `LASTEXITCODE=0`; standard-library introspection only. |

The normal-account metadata check also reported `sys.prefix` as the project `.venv` and `sys.base_prefix` as the private base installation. Thus the project is invoking the intended environment, and that environment can start once its base installation is accessible.

## Access-control evidence and alternatives

`whoami /user` in the restricted session returned `desktop-u5n1qjs\codexsandboxoffline`; its enabled groups included `CodexSandboxUsers`. `icacls .venv\Scripts\python.exe` gave inherited Modify access to `CodexSandboxUsers`. In contrast, `icacls C:\Users\Laptop\AppData\Local\Python\pythoncore-3.14-64\python.exe` returned `Access is denied` from that session. Normal-account inspection showed the `Python` directory, `pythoncore-3.14-64` directory and base `python.exe` allowed only `SYSTEM`, `Administrators`, and `Laptop` (Full Control). The parent `AppData` and `AppData\Local` have sandbox read/execute rights, but the narrower `Python` directory does not. This explains why the project-local redirector is readable while its base target cannot start.

The normal account successfully executed the **same `.venv` path inside OneDrive**. Both the virtual launcher and base executable appeared as ordinary `Archive` files, with no reparse target shown. This rules out an inherently broken OneDrive placeholder or current lock as the observed cause; it does not assess every possible future synchronization issue. There was no observed Windows Defender/AppLocker block, and a broader security-event investigation was unnecessary to identify the access boundary. The launcher is present, signed, and functional in the account with base-path access. No package import failure occurred during the failed sandbox attempts because Python never started; installed-package metadata subsequently matched all pins under the normal account.

## Minimal verification and repair procedure

1. Open a **normal, non-sandboxed PowerShell** as `DESKTOP-U5N1QJS\Laptop`; stay in the repository root. Use the existing direct interpreter path, without activating or changing `.venv`:

   ```powershell
   whoami
   & '.\.venv\Scripts\python.exe' -B --version
   $LASTEXITCODE
   & '.\.venv\Scripts\python.exe' -B -c 'import sys; print(sys.executable); print(sys._base_executable)'
   $LASTEXITCODE
   ```

2. Expect `Laptop`, Python 3.14.3, two zero exit codes, `sys.executable` inside the project `.venv`, and `sys._base_executable` at the private base installation. These interpreter-only checks already passed in this diagnosis. For a later authorized professor rehearsal, use the commands in [the demonstration audit](PROFESSOR_DEMONSTRATION_READINESS_2026-11-03.md) and capture their outputs separately. This diagnosis did **not** execute M1–M6.
3. Keep the existing `.venv`. Rebuilding it would still point a new environment at a base interpreter and is not justified by the observed failure. No rollback is needed for the recommended account choice because it changes no file. To undo a test session, close that PowerShell window. If an administrator later authorizes an ACL or installation change for sandbox execution, document the original ACL and verify the narrow grant and its rollback before doing so; that is a separate decision.

## Demonstration impact

The earlier audit's “no successful audit-time command execution” remains accurate for its sandboxed attempts. This diagnosis establishes only that the existing interpreter and pinned package metadata work under the normal owner account; it has **not** rerun an application workflow or verified M1–M6 behavior today. Historical M1–M5 and M6Q engineering results retain their prior status. A normal-account professor rehearsal is now possible at the interpreter level, subject to the separate M4/M5 Git revision prerequisite, fresh external-data paths, and the M6 fresh-run/assessor-pin limitations described in the demonstration audit. No research result is established by this environment check.
