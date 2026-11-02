param([string]$Label = 'live', [string]$OutputDirectory = 'live_m6')
$ErrorActionPreference = 'Stop'
$dir = $PSScriptRoot
$root = (Resolve-Path (Join-Path $dir '..\..\..')).Path
$python = (Resolve-Path (Join-Path $root '.venv\Scripts\python.exe')).Path
$env:CHAINGUARD_TRUSTED_CODE_REVISION = '8b27b5a980a87887be66c409c5a6a31d415a3326'
$env:CHAINGUARD_M6Q_OUTPUT = $OutputDirectory
$env:PYTHONPATH = $root
$out = Join-Path $dir "$Label.stdout.log"
$err = Join-Path $dir "$Label.stderr.log"
$meta = Join-Path $dir "$Label.run.json"
if ((Test-Path $out) -or (Test-Path $err) -or (Test-Path $meta)) { throw 'Live run evidence exists.' }
$start = Get-Date
$timer = [Diagnostics.Stopwatch]::StartNew()
$process = Start-Process -FilePath $python -ArgumentList @('-B',
    'results/completion_sprint_2026-11-02/H22-H25/qualify_live.py') -WorkingDirectory $root `
    -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
$timer.Stop()
$end = Get-Date
[ordered]@{
    command = '.\.venv\Scripts\python.exe -B results/completion_sprint_2026-11-02/H22-H25/qualify_live.py'
    revision_pin = $env:CHAINGUARD_TRUSTED_CODE_REVISION
    revision_source = 'explicit project owner reply; no Git command run by agent'
    output_directory = $OutputDirectory
    start_local = $start.ToString('o')
    end_local = $end.ToString('o')
    elapsed_seconds = $timer.Elapsed.TotalSeconds
    exit_code = $process.ExitCode
    stdout_log = $out
    stderr_log = $err
} | ConvertTo-Json | Set-Content -LiteralPath $meta -Encoding utf8
exit $process.ExitCode
