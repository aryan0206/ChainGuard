param([string]$Label = 'targeted')
$ErrorActionPreference = 'Stop'
$dir = $PSScriptRoot
$root = (Resolve-Path (Join-Path $dir '..\..\..')).Path
$python = (Resolve-Path (Join-Path $root '.venv\Scripts\python.exe')).Path
$env:CHAINGUARD_TRUSTED_CODE_REVISION = 'a' * 40
$tests = @(
    'tests.test_m6_live_profile.LiveProfileTests.test_trusted_revision_is_required_and_never_looked_up_with_git',
    'tests.test_m6_live_runtime.RuntimeTests.test_assessor_stream_retains_commit_handler_and_exact_sink_bytes',
    'tests.test_m6_live_server.LiveServerTests.test_malformed_protocol_frame_is_distinct_from_rejected_tool_call',
    'tests.test_m6_live_server.LiveServerTests.test_real_stdio_multibyte_byte_boundary',
    'tests.test_m6_live_server.LiveServerTests.test_real_stdio_valid_mcp_rejections_have_zero_arrivals')
$out = Join-Path $dir "$Label.stdout.log"
$err = Join-Path $dir "$Label.stderr.log"
$meta = Join-Path $dir "$Label.run.json"
if ((Test-Path $out) -or (Test-Path $err) -or (Test-Path $meta)) { throw 'Targeted evidence exists.' }
$start = Get-Date
$timer = [Diagnostics.Stopwatch]::StartNew()
$process = Start-Process -FilePath $python -ArgumentList (@('-B', '-m', 'unittest', '-v') + $tests) `
    -WorkingDirectory $root -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput $out `
    -RedirectStandardError $err
$timer.Stop()
$end = Get-Date
[ordered]@{
    command = '.\.venv\Scripts\python.exe -B -m unittest -v ' + ($tests -join ' ')
    revision_source = 'synthetic engineering environment value, not a real Git revision'
    start_local = $start.ToString('o')
    end_local = $end.ToString('o')
    elapsed_seconds = $timer.Elapsed.TotalSeconds
    exit_code = $process.ExitCode
    stdout_log = $out
    stderr_log = $err
} | ConvertTo-Json | Set-Content -LiteralPath $meta -Encoding utf8
exit $process.ExitCode
