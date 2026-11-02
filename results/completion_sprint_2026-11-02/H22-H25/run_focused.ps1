param([string]$Label = 'focused')
$ErrorActionPreference = 'Stop'
$dir = $PSScriptRoot
$root = (Resolve-Path (Join-Path $dir '..\..\..')).Path
$python = (Resolve-Path (Join-Path $root '.venv\Scripts\python.exe')).Path
$env:CHAINGUARD_TRUSTED_CODE_REVISION = 'a' * 40 # Synthetic engineering pin only.
$tests = @('tests.test_m6_live_profile', 'tests.test_m6_live_runtime',
    'tests.test_m6_live_server', 'tests.test_m6_live_authorization',
    'tests.test_m6_live_evidence', 'tests.test_m6_live_seal',
    'tests.test_m6_live_verifier', 'tests.test_m6_live_acceptance')
$arguments = @('-B', '-m', 'unittest', '-v') + $tests
$out = Join-Path $dir "$Label.stdout.log"
$err = Join-Path $dir "$Label.stderr.log"
$meta = Join-Path $dir "$Label.run.json"
if ((Test-Path $out) -or (Test-Path $err) -or (Test-Path $meta)) {
    throw 'Focused evidence already exists.'
}
$start = Get-Date
$timer = [Diagnostics.Stopwatch]::StartNew()
$process = Start-Process -FilePath $python -ArgumentList $arguments -WorkingDirectory $root `
    -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
$timer.Stop()
$end = Get-Date
[ordered]@{
    command = '.\.venv\Scripts\python.exe -B -m unittest -v ' + ($tests -join ' ')
    revision_source = 'synthetic engineering environment value, not a real Git revision'
    start_local = $start.ToString('o')
    end_local = $end.ToString('o')
    elapsed_seconds = $timer.Elapsed.TotalSeconds
    exit_code = $process.ExitCode
    stdout_log = $out
    stderr_log = $err
} | ConvertTo-Json | Set-Content -LiteralPath $meta -Encoding utf8
exit $process.ExitCode
