$ErrorActionPreference = 'Stop'
$dir = $PSScriptRoot
$root = (Resolve-Path (Join-Path $dir '..\..\..')).Path
$python = (Resolve-Path (Join-Path $root '.venv\Scripts\python.exe')).Path
$env:CHAINGUARD_TRUSTED_CODE_REVISION = 'a' * 40
$test = 'tests.test_m6_live_runtime.RuntimeTests.test_inherited_assessor_endpoint_cannot_redirect_child_sink'
$out = Join-Path $dir 'env_guard.stdout.log'
$err = Join-Path $dir 'env_guard.stderr.log'
$meta = Join-Path $dir 'env_guard.run.json'
if ((Test-Path $out) -or (Test-Path $err) -or (Test-Path $meta)) { throw 'Environment guard evidence exists.' }
$start = Get-Date
$timer = [Diagnostics.Stopwatch]::StartNew()
$process = Start-Process -FilePath $python -ArgumentList @('-B', '-m', 'unittest', '-v', $test) `
    -WorkingDirectory $root -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput $out `
    -RedirectStandardError $err
$timer.Stop()
$end = Get-Date
[ordered]@{
    command = ".\.venv\Scripts\python.exe -B -m unittest -v $test"
    revision_source = 'synthetic engineering environment value, not a real Git revision'
    start_local = $start.ToString('o')
    end_local = $end.ToString('o')
    elapsed_seconds = $timer.Elapsed.TotalSeconds
    exit_code = $process.ExitCode
    stdout_log = $out
    stderr_log = $err
} | ConvertTo-Json | Set-Content -LiteralPath $meta -Encoding utf8
exit $process.ExitCode
