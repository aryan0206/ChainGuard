$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$root = (Resolve-Path (Join-Path $here '..\..\..')).Path
$python = (Resolve-Path (Join-Path $root '.venv\Scripts\python.exe')).Path
$out = Join-Path $here 'metamorphic_development.stdout.log'
$err = Join-Path $here 'metamorphic_development.stderr.log'
$meta = Join-Path $here 'metamorphic_development.run.json'
if ((Test-Path $out) -or (Test-Path $err) -or (Test-Path $meta)) { throw 'Evidence already exists' }
$args = @('-B', 'results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/build_metamorphic_development.py')
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
