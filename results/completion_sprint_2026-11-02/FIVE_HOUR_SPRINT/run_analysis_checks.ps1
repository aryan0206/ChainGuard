$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$root = (Resolve-Path (Join-Path $here '..\..\..')).Path
$python = (Resolve-Path (Join-Path $root '.venv\Scripts\python.exe')).Path
$env:PYTHONPATH = $here
$steps = @(
    @('-B', 'results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/test_research_metrics.py'),
    @('-B', 'results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/prepare_development_metrics.py'),
    @('-B', 'results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/research_metrics.py',
      'results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/development_metric_input.json',
      'results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/development_metric_result.json')
)
$records = @()
for ($i = 0; $i -lt $steps.Count; $i++) {
    $out = Join-Path $here "analysis_$i.stdout.log"
    $err = Join-Path $here "analysis_$i.stderr.log"
    if ((Test-Path $out) -or (Test-Path $err)) { throw "Evidence exists for step $i" }
    $start = Get-Date
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $process = Start-Process -FilePath $python -ArgumentList $steps[$i] -WorkingDirectory $root `
        -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
    $timer.Stop()
    $records += [ordered]@{
        command = '.\.venv\Scripts\python.exe ' + ($steps[$i] -join ' ')
        start_local = $start.ToString('o')
        end_local = (Get-Date).ToString('o')
        elapsed_seconds = $timer.Elapsed.TotalSeconds
        exit_code = $process.ExitCode
        stdout = $out
        stderr = $err
    }
    if ($process.ExitCode -ne 0) { break }
}
[ordered]@{steps=$records;python_version=(& $python --version 2>&1 | Out-String).Trim();
    powershell_version=$PSVersionTable.PSVersion.ToString()} |
    ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $here 'analysis_checks.run.json') -Encoding utf8
exit $records[-1].exit_code
