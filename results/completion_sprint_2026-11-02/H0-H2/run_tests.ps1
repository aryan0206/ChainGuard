param(
    [ValidateSet('focused', 'full', 'isolated')]
    [string]$Run,
    [string]$EvidenceName = $Run
)

$ErrorActionPreference = 'Stop'
$dir = $PSScriptRoot
$project = (Resolve-Path (Join-Path $dir '..\..\..')).Path
$python = (Resolve-Path (Join-Path $project '.venv\Scripts\python.exe')).Path
$arguments = if ($Run -eq 'focused') {
    @('-B', '-m', 'unittest', '-v', 'tests.test_m6_live_verifier', 'tests.test_m6_live_acceptance')
} elseif ($Run -eq 'isolated') {
    @('-B', '-m', 'unittest', '-v', 'tests.test_m6_live_runtime.RuntimeTests.test_worker_rejects_auxiliary_label_with_tool_call_frame')
} else {
    @('-B', '-m', 'unittest', 'discover', '-s', 'tests')
}
$stdout = Join-Path $dir "$EvidenceName.stdout.log"
$stderr = Join-Path $dir "$EvidenceName.stderr.log"
$metadata = Join-Path $dir "$EvidenceName.run.json"
if ((Test-Path $stdout) -or (Test-Path $stderr) -or (Test-Path $metadata)) {
    throw "Existing $EvidenceName evidence would be overwritten."
}

$start = Get-Date
$timer = [System.Diagnostics.Stopwatch]::StartNew()
$process = Start-Process -FilePath $python -ArgumentList $arguments -WorkingDirectory $project -Wait -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
$timer.Stop()
$end = Get-Date
[ordered]@{
    run = $Run
    evidence_name = $EvidenceName
    command = if ($Run -eq 'focused') { '.\.venv\Scripts\python.exe -B -m unittest -v tests.test_m6_live_verifier tests.test_m6_live_acceptance' } elseif ($Run -eq 'isolated') { '.\.venv\Scripts\python.exe -B -m unittest -v tests.test_m6_live_runtime.RuntimeTests.test_worker_rejects_auxiliary_label_with_tool_call_frame' } else { '.\.venv\Scripts\python.exe -B -m unittest discover -s tests' }
    working_directory = $project
    start_local = $start.ToString('o')
    end_local = $end.ToString('o')
    start_utc = $start.ToUniversalTime().ToString('o')
    end_utc = $end.ToUniversalTime().ToString('o')
    elapsed_seconds = $timer.Elapsed.TotalSeconds
    exit_code = $process.ExitCode
    stdout_log = $stdout
    stderr_log = $stderr
} | ConvertTo-Json | Set-Content -LiteralPath $metadata -Encoding utf8
Get-Content -LiteralPath $metadata
