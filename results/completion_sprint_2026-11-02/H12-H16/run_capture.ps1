$ErrorActionPreference = 'Stop'
$dir = $PSScriptRoot
$root = (Resolve-Path (Join-Path $dir '..\..\..')).Path
$python = (Resolve-Path (Join-Path $root '.venv\Scripts\python.exe')).Path
$out = Join-Path $dir 'capture.stdout.log'
$err = Join-Path $dir 'capture.stderr.log'
$meta = Join-Path $dir 'capture.run.json'
if ((Test-Path $out) -or (Test-Path $err) -or (Test-Path $meta)) { throw 'Existing capture evidence would be overwritten.' }
$start = Get-Date
$timer = [Diagnostics.Stopwatch]::StartNew()
$process = Start-Process -FilePath $python -ArgumentList @('-B', 'results/completion_sprint_2026-11-02/H12-H16/capture_development.py') -WorkingDirectory $root -Wait -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
$timer.Stop()
$end = Get-Date
[ordered]@{
    command = '.\.venv\Scripts\python.exe -B results/completion_sprint_2026-11-02/H12-H16/capture_development.py'
    start_local = $start.ToString('o')
    end_local = $end.ToString('o')
    elapsed_seconds = $timer.Elapsed.TotalSeconds
    exit_code = $process.ExitCode
    stdout_log = $out
    stderr_log = $err
} | ConvertTo-Json | Set-Content -LiteralPath $meta -Encoding utf8
Get-Content -LiteralPath $meta
