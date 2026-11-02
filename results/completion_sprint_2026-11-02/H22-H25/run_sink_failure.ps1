$ErrorActionPreference = 'Stop'
$dir = $PSScriptRoot
$root = (Resolve-Path (Join-Path $dir '..\..\..')).Path
$python = (Resolve-Path (Join-Path $root '.venv\Scripts\python.exe')).Path
$env:CHAINGUARD_TRUSTED_CODE_REVISION = 'a' * 40
$test = 'tests.test_m6_live_runtime.RuntimeTests.test_unavailable_assessor_sink_halts_without_successful_arrival'
$out = Join-Path $dir 'sink_failure.stdout.log'
$err = Join-Path $dir 'sink_failure.stderr.log'
$meta = Join-Path $dir 'sink_failure.run.json'
if ((Test-Path $out) -or (Test-Path $err) -or (Test-Path $meta)) { throw 'Sink failure evidence exists.' }
$start = Get-Date
$timer = [Diagnostics.Stopwatch]::StartNew()
$process = Start-Process -FilePath $python -ArgumentList @('-B', '-m', 'unittest', '-v', $test) `
    -WorkingDirectory $root -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput $out `
    -RedirectStandardError $err
$timer.Stop()
$end = Get-Date
[ordered]@{
    command = ".\.venv\Scripts\python.exe -B -m unittest -v $test"
    revision_source = 'synthetic engineering environment value, not a real Git revision'
    start_local = $start.ToString('o')
    end_local = $end.ToString('o')
    elapsed_seconds = $timer.Elapsed.TotalSeconds
    exit_code = $process.ExitCode
    stdout_log = $out
    stderr_log = $err
} | ConvertTo-Json | Set-Content -LiteralPath $meta -Encoding utf8
exit $process.ExitCode
