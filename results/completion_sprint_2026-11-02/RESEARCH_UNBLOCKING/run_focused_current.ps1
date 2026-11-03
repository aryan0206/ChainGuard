$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$root = (Resolve-Path (Join-Path $here '..\..\..')).Path
$python = (Resolve-Path (Join-Path $root '.venv\Scripts\python.exe')).Path
$tests = @('tests.test_m6_live_profile', 'tests.test_m6_live_runtime',
    'tests.test_m6_live_server', 'tests.test_m6_live_authorization',
    'tests.test_m6_live_evidence', 'tests.test_m6_live_seal',
    'tests.test_m6_live_verifier', 'tests.test_m6_live_acceptance')
$args = @('-B', '-m', 'unittest', '-v') + $tests
$out = Join-Path $here 'focused_current_retry.stdout.log'
$err = Join-Path $here 'focused_current_retry.stderr.log'
$meta = Join-Path $here 'focused_current_retry.run.json'
if ((Test-Path $out) -or (Test-Path $err) -or (Test-Path $meta)) { throw 'Current-source evidence already exists.' }
$env:CHAINGUARD_TRUSTED_CODE_REVISION = 'a' * 40 # Engineering test input only; not a source revision or qualification pin.
$sources = @('chainguard/m6_live_profile.py', 'chainguard/m6_live_runtime.py',
    'chainguard/m6_live_authorization.py', 'chainguard/m6_live_witness.py',
    'chainguard/m6_controlled_server.py', 'chainguard/m6_live_evidence.py',
    'chainguard/m6_live_seal.py', 'chainguard/m6_live_verifier.py',
    'chainguard/acceptance.py')
$hashes = [ordered]@{}
foreach ($name in $sources) { $hashes[$name] = (Get-FileHash -LiteralPath (Join-Path $root $name) -Algorithm SHA256).Hash.ToLowerInvariant() }
$start = Get-Date
$timer = [Diagnostics.Stopwatch]::StartNew()
$process = Start-Process -FilePath $python -ArgumentList $args -WorkingDirectory $root `
    -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
$timer.Stop()
$end = Get-Date
[ordered]@{
    command = '.\.venv\Scripts\python.exe -B -m unittest -v ' + ($tests -join ' ')
    start_local = $start.ToString('o')
    end_local = $end.ToString('o')
    elapsed_seconds = $timer.Elapsed.TotalSeconds
    exit_code = $process.ExitCode
    revision_source = 'synthetic a*40 engineering-test environment value only; no current-source revision assertion'
    python_version = (& $python --version 2>&1 | Out-String).Trim()
    powershell_version = $PSVersionTable.PSVersion.ToString()
    os = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
    source_sha256 = $hashes
    stdout_log = $out
    stderr_log = $err
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $meta -Encoding utf8
exit $process.ExitCode
