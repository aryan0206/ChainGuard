$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$root = (Resolve-Path (Join-Path $here '..\..\..')).Path
$python = (Resolve-Path (Join-Path $root '.venv\Scripts\python.exe')).Path
$env:CHAINGUARD_E12_RETRY = '1'
$out = Join-Path $here 'e12_revision.stdout.log'
$err = Join-Path $here 'e12_revision.stderr.log'
$meta = Join-Path $here 'e12_revision.run.json'
if ((Test-Path $out) -or (Test-Path $err) -or (Test-Path $meta)) { throw 'Evidence already exists' }
$args = @('-B', 'results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/benchmark_development.py')
$start = Get-Date
$timer = [Diagnostics.Stopwatch]::StartNew()
$process = Start-Process -FilePath $python -ArgumentList $args -WorkingDirectory $root `
    -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
$timer.Stop()
[ordered]@{command='\.venv\Scripts\python.exe ' + ($args -join ' ');
    environment='CHAINGUARD_E12_RETRY=1';start_local=$start.ToString('o');
    end_local=(Get-Date).ToString('o');elapsed_seconds=$timer.Elapsed.TotalSeconds;
    exit_code=$process.ExitCode;stdout=$out;stderr=$err} |
    ConvertTo-Json | Set-Content -LiteralPath $meta -Encoding utf8
exit $process.ExitCode
