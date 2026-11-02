$ErrorActionPreference = 'Stop'
$dir = $PSScriptRoot
$root = (Resolve-Path (Join-Path $dir '..\..\..')).Path
$python = (Resolve-Path (Join-Path $root '.venv\Scripts\python.exe')).Path
$args = @('-B', '-m', 'unittest', '-v',
    'tests.test_m6_live_runtime.RuntimeTests.test_timeout_and_malformed_response_halt_without_replay',
    'tests.test_m6_live_runtime.RuntimeTests.test_worker_rejects_auxiliary_label_with_tool_call_frame')
$out = Join-Path $dir 'targeted.stdout.log'
$err = Join-Path $dir 'targeted.stderr.log'
$meta = Join-Path $dir 'targeted.run.json'
if ((Test-Path $out) -or (Test-Path $err) -or (Test-Path $meta)) { throw 'Targeted evidence already exists.' }
$start = Get-Date
$timer = [Diagnostics.Stopwatch]::StartNew()
$process = Start-Process -FilePath $python -ArgumentList $args -WorkingDirectory $root -Wait -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
$timer.Stop()
$end = Get-Date
[ordered]@{
    command = '.\.venv\Scripts\python.exe -B -m unittest -v tests.test_m6_live_runtime.RuntimeTests.test_timeout_and_malformed_response_halt_without_replay tests.test_m6_live_runtime.RuntimeTests.test_worker_rejects_auxiliary_label_with_tool_call_frame'
    start_local = $start.ToString('o')
    end_local = $end.ToString('o')
    elapsed_seconds = $timer.Elapsed.TotalSeconds
    exit_code = $process.ExitCode
    stdout_log = $out
    stderr_log = $err
} | ConvertTo-Json | Set-Content -LiteralPath $meta -Encoding utf8
