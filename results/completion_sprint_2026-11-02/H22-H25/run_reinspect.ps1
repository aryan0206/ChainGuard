$ErrorActionPreference = 'Stop'
$dir = $PSScriptRoot
$root = (Resolve-Path (Join-Path $dir '..\..\..')).Path
$python = (Resolve-Path (Join-Path $root '.venv\Scripts\python.exe')).Path
$env:CHAINGUARD_TRUSTED_CODE_REVISION = '8b27b5a980a87887be66c409c5a6a31d415a3326'
$env:PYTHONPATH = $root
$out = Join-Path $dir 'reinspect.stdout.log'
$err = Join-Path $dir 'reinspect.stderr.log'
$meta = Join-Path $dir 'reinspect.run.json'
if ((Test-Path $out) -or (Test-Path $err) -or (Test-Path $meta)) { throw 'Reinspection evidence exists.' }
$start = Get-Date
$timer = [Diagnostics.Stopwatch]::StartNew()
$process = Start-Process -FilePath $python -ArgumentList @('-B',
    'results/completion_sprint_2026-11-02/H22-H25/offline_reinspect.py') `
    -WorkingDirectory $root -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput $out `
    -RedirectStandardError $err
$timer.Stop()
$end = Get-Date
[ordered]@{
    command = '.\.venv\Scripts\python.exe -B results/completion_sprint_2026-11-02/H22-H25/offline_reinspect.py'
    revision_pin = $env:CHAINGUARD_TRUSTED_CODE_REVISION
    start_local = $start.ToString('o')
    end_local = $end.ToString('o')
    elapsed_seconds = $timer.Elapsed.TotalSeconds
    exit_code = $process.ExitCode
    stdout_log = $out
    stderr_log = $err
} | ConvertTo-Json | Set-Content -LiteralPath $meta -Encoding utf8
exit $process.ExitCode
