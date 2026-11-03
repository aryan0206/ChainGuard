$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$root = (Resolve-Path (Join-Path $here '..\..\..')).Path
$python = (Resolve-Path (Join-Path $root '.venv\Scripts\python.exe')).Path
$env:PYTHONPATH = $here
$out = Join-Path $here 'metrics_revision.stdout.log'
$err = Join-Path $here 'metrics_revision.stderr.log'
$meta = Join-Path $here 'metrics_revision.run.json'
if ((Test-Path $out) -or (Test-Path $err) -or (Test-Path $meta)) { throw 'Evidence already exists' }
$args = @('-B', 'results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/test_research_metrics.py')
$start = Get-Date
$timer = [Diagnostics.Stopwatch]::StartNew()
$process = Start-Process -FilePath $python -ArgumentList $args -WorkingDirectory $root `
    -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
$timer.Stop()
[ordered]@{command='\.venv\Scripts\python.exe ' + ($args -join ' ');
    start_local=$start.ToString('o');end_local=(Get-Date).ToString('o');
    elapsed_seconds=$timer.Elapsed.TotalSeconds;exit_code=$process.ExitCode;
    stdout=$out;stderr=$err} | ConvertTo-Json | Set-Content -LiteralPath $meta -Encoding utf8
exit $process.ExitCode
