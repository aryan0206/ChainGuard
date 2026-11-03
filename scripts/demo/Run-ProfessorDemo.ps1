# ChainGuard professor demonstration suite. Compatible with Windows PowerShell 5.1.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$python = Join-Path $repo '.venv\Scripts\python.exe'
$historical = Join-Path $repo 'results\completion_sprint_2026-11-02\FIVE_HOUR_SPRINT\live_m6_current'
$requiredHistorical = @('case_results.json','controls.json','offline_verification.json',
    'fresh_process_reinspection.json','fresh_submission_readback.json',
    'witness_primary\host.jsonl','witness_primary\child.jsonl','witness_primary\sink.jsonl')
$run = $null
$manifest = [ordered]@{ schema_version = 1; suite = 'separate M1-M5 demonstrations and retained M6Q inspection';
    repository = $repo; output_directory = $null; started_utc = (Get-Date).ToUniversalTime().ToString('o');
    ended_utc = $null; status = 'RUNNING'; failed_step = $null; steps = @(); artifacts = [ordered]@{} }

function Require([bool]$condition, [string]$message) {
    if (-not $condition) { throw $message }
}
function Save-Manifest {
    if ($null -ne $run) {
        $path = Join-Path $run 'run-manifest.json'
        $temp = Join-Path $run 'run-manifest.tmp'
        $manifest | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $temp -Encoding UTF8
        Move-Item -LiteralPath $temp -Destination $path -Force
    }
}
function Read-Json([string]$path) {
    Require (Test-Path -LiteralPath $path -PathType Leaf) "Missing output: $path"
    return (Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json)
}
function Quote-Arg([string]$value) {
    # Windows PowerShell 5.1 uses .NET Framework, whose ProcessStartInfo has
    # Arguments but no ArgumentList. Serialize one array element using the
    # Windows argv quoting rules; ProcessStartInfo starts Python directly,
    # without cmd.exe or a PowerShell command-string parser.
    Require ($null -ne $value -and -not $value.Contains([char]0)) 'Invalid process argument'
    $quoted = New-Object Text.StringBuilder
    [void]$quoted.Append('"')
    $slashes = 0
    foreach ($character in $value.ToCharArray()) {
        if ($character -eq [char]'\') {
            $slashes++
        } elseif ($character -eq [char]'"') {
            [void]$quoted.Append([char]'\', (2 * $slashes + 1))
            [void]$quoted.Append($character)
            $slashes = 0
        } else {
            if ($slashes) { [void]$quoted.Append([char]'\', $slashes) }
            [void]$quoted.Append($character)
            $slashes = 0
        }
    }
    if ($slashes) { [void]$quoted.Append([char]'\', (2 * $slashes)) }
    [void]$quoted.Append('"')
    return $quoted.ToString()
}
function Invoke-Child([string]$name, [string[]]$arguments) {
    $logdir = Join-Path $run 'logs'
    $stdout = Join-Path $logdir ($name + '.stdout.log')
    $stderr = Join-Path $logdir ($name + '.stderr.log')
    Require (-not (Test-Path -LiteralPath $stdout) -and -not (Test-Path -LiteralPath $stderr)) "Log path already exists for $name"
    $command = @($python) + $arguments
    $step = [ordered]@{ name = $name; status = 'RUNNING'; command = $command; working_directory = $repo;
        started_utc = (Get-Date).ToUniversalTime().ToString('o'); ended_utc = $null; exit_code = $null;
        stdout_log = $stdout; stderr_log = $stderr; artifacts = @(); verification = [ordered]@{} }
    $manifest.steps += $step
    Save-Manifest
    Write-Host "`n=== $name ==="
    Write-Host ('Command: ' + (($command | ForEach-Object { Quote-Arg $_ }) -join ' '))
    Write-Host ('Started UTC: ' + $step.started_utc)
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $python
    $psi.Arguments = ($arguments | ForEach-Object { Quote-Arg $_ }) -join ' '
    $psi.WorkingDirectory = $repo
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.EnvironmentVariables['PYTHONUTF8'] = '1'
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $psi
    $outStream = $null; $errStream = $null
    $started = $false
    try {
        $started = $process.Start()
        Require $started "Could not start $name"
        # Byte streams are copied directly to files. Console previews are read from those files.
        $outStream = [IO.File]::Open($stdout, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
        $errStream = [IO.File]::Open($stderr, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
        $outTask = $process.StandardOutput.BaseStream.CopyToAsync($outStream)
        $errTask = $process.StandardError.BaseStream.CopyToAsync($errStream)
        while (-not $process.HasExited) {
            Start-Sleep -Milliseconds 500
            Write-Progress -Activity $name -Status 'Running; raw stdout and stderr are being preserved' -PercentComplete 0
        }
        $process.WaitForExit()
        [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($outTask, $errTask))
        $outStream.Flush(); $errStream.Flush()
        $step.exit_code = $process.ExitCode
        $step.status = if ($step.exit_code -eq 0) { 'PROCESS_OK' } else { 'FAILED' }
    } finally {
        Write-Progress -Activity $name -Completed
        if ($null -ne $outStream) { $outStream.Dispose() }
        if ($null -ne $errStream) { $errStream.Dispose() }
        if ($started -and -not $process.HasExited) { $process.Kill(); $process.WaitForExit() }
        $process.Dispose()
        if ($step.status -eq 'RUNNING') { $step.status = 'FAILED' }
        $step.ended_utc = (Get-Date).ToUniversalTime().ToString('o')
        Save-Manifest
    }
    Write-Host ('Ended UTC: ' + $step.ended_utc + '; exit code: ' + $step.exit_code)
    foreach ($log in @($stdout, $stderr)) {
        if ((Get-Item -LiteralPath $log).Length -gt 0) {
            Write-Host ('Output preview from ' + $log + ':')
            Get-Content -LiteralPath $log -Encoding UTF8 -TotalCount 12 | ForEach-Object {
                $line = [string]$_
                if ($line.Length -gt 300) { $line = $line.Substring(0, 300) + ' ... [line truncated in console]' }
                Write-Host $line
            }
            Write-Host '(Full raw output remains in the log.)'
        }
    }
    Require ($step.exit_code -eq 0) "$name exited with $($step.exit_code); inspect $stdout and $stderr"
    return $step
}
function Complete-Step($step, $verification, [string[]]$artifacts) {
    $step.verification = $verification
    $step.artifacts = $artifacts
    $step.status = 'PASSED'
    Save-Manifest
    Write-Host ('PASS ' + $step.name + ': ' + ($verification | ConvertTo-Json -Compress -Depth 8))
}

try {
    Require (Test-Path -LiteralPath $repo -PathType Container) "Repository root missing: $repo"
    Require (Test-Path -LiteralPath $python -PathType Leaf) "Existing virtual environment Python missing: $python"
    foreach ($relative in $requiredHistorical) {
        Require (Test-Path -LiteralPath (Join-Path $historical $relative) -PathType Leaf) "Retained M6Q evidence missing: $relative"
    }
    Require ($env:TEMP -and (Test-Path -LiteralPath $env:TEMP -PathType Container)) 'User temporary directory is unavailable'
    $temp = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')
    Require (-not ($temp -eq $repo -or $temp.StartsWith($repo + '\', [StringComparison]::OrdinalIgnoreCase))) 'TEMP resolves inside the repository'
    $run = Join-Path $temp ('chainguard-professor-' + [guid]::NewGuid().ToString('N'))
    Require (-not (Test-Path -LiteralPath $run)) "Refusing existing output path: $run"
    New-Item -ItemType Directory -Path $run -ErrorAction Stop | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $run 'logs') -ErrorAction Stop | Out-Null
    $manifest.output_directory = $run
    Save-Manifest
    Write-Host "Evidence and logs: $run"
    Write-Host 'This is a suite of separate demonstrations, not one continuous MCP event stream.'
    Write-Host 'M5 starts its own M4 run after pre-registration. M6Q is read-only historical inspection.'

    $version = Invoke-Child 'preflight-python-version' @('-B','--version')
    Complete-Step $version ([ordered]@{ python_version = (Get-Content $version.stdout_log -Raw).Trim() }) @()
    $imports = Invoke-Child 'preflight-imports' @('-B','-c','import mcp, cryptography, chainguard.client, chainguard.m2, chainguard.m3, chainguard.m4, chainguard.m5, chainguard.verifier; print("IMPORTS_OK")')
    Require ((Get-Content $imports.stdout_log -Raw).Trim() -eq 'IMPORTS_OK') 'Required Python imports did not report IMPORTS_OK'
    Complete-Step $imports ([ordered]@{ imports = 'PASS'; retained_m6q_files = $requiredHistorical }) @()

    $m1 = Invoke-Child 'M1-client' @('-B','-m','chainguard.client')
    $j = Read-Json $m1.stdout_log
    Require ($j.tools.Count -eq 2 -and $j.success.isError -eq $false -and $j.controlled_error.isError -eq $true -and $j.success_after_error.isError -eq $false) 'M1 result sequence mismatch'
    Complete-Step $m1 ([ordered]@{ protocol_version = $j.protocol_version; server = $j.server; controlled_error = $j.controlled_error.isError; recovered = $true }) @()

    $m2 = Invoke-Child 'M2-replay' @('-B','-m','chainguard.m2')
    $j = Read-Json $m2.stdout_log
    Require ($j.execution -eq 'REPLAY_ONLY_NO_TOOL_EXECUTION' -and $j.b2_equivalence -eq 'PASS_AT_EVERY_VALID_PROPOSAL_PREFIX' -and $j.fixture_count -eq $j.fixtures.Count) 'M2 replay/equivalence mismatch'
    Complete-Step $m2 ([ordered]@{ fixture_count = $j.fixture_count; valid_proposal_prefixes = $j.valid_proposal_prefixes; b2_equivalence = $j.b2_equivalence }) @()

    $m3dir = Join-Path $run 'm3'
    New-Item -ItemType Directory -Path $m3dir -ErrorAction Stop | Out-Null
    $m3db = Join-Path $m3dir 'audit.sqlite'
    Require (-not (Test-Path $m3db)) 'M3 database already exists'
    $m3 = Invoke-Child 'M3-durable' @('-B','-m','chainguard.m3','demo','--db',$m3db)
    $j = Read-Json $m3.stdout_log
    Require ((Test-Path $m3db -PathType Leaf) -and $j.crypto_evidence_implemented -eq $false -and (($j.tool_outcomes -join ',') -eq 'succeeded,failed,succeeded') -and $j.closure -eq 'CLOSED_UNSEALED') 'M3 database or result mismatch'
    Complete-Step $m3 ([ordered]@{ record_count = $j.record_count; closure = $j.closure; tool_outcomes = $j.tool_outcomes; confirmed_transactions = $j.confirmed_transactions }) @($m3db)
    $manifest.artifacts.m3_database = $m3db

    $m4dir = Join-Path $run 'm4'
    Require (-not (Test-Path $m4dir)) 'M4 output directory already exists'
    $m4 = Invoke-Child 'M4-signed' @('-B','-m','chainguard.m4','demo','--directory',$m4dir)
    $j = Read-Json $m4.stdout_log
    $m4files = @('audit.sqlite','evidence.json','expected.json','configuration.json','fixture-private.pem','fixture-public.pem') | ForEach-Object { Join-Path $m4dir $_ }
    foreach ($file in $m4files) { Require (Test-Path $file -PathType Leaf) "M4 artifact missing: $file" }
    Require ($j.milestone -eq 'M4' -and $j.offline_verifier_exit_code -eq 0 -and $j.offline_verification.inspection_passed -eq $true -and $j.monitor_exited_before_verification -eq $true) 'M4 signed run or internal inspection failed'
    Complete-Step $m4 ([ordered]@{ record_count = $j.record_count; internal_inspection_passed = $j.offline_verification.inspection_passed; monitor_exited_before_verification = $true }) $m4files
    $manifest.artifacts.m4 = $m4files

    $v = Invoke-Child 'M4-standalone-verifier' @('-B','-m','chainguard.verifier','--package',(Join-Path $m4dir 'evidence.json'),'--expected',(Join-Path $m4dir 'expected.json'),'--config',(Join-Path $m4dir 'configuration.json'),'--public-key',(Join-Path $m4dir 'fixture-public.pem'),'--key-id','chainguard-m4-fixture-key')
    $j = Read-Json $v.stdout_log
    Require ($j.mode -eq 'INSPECT' -and $j.fresh_submission -eq 'NOT_CHECKED' -and $j.inspection_passed -eq $true) 'Standalone M4 inspection failed'
    foreach ($name in @('schema_lifecycle','commitment_integrity','trusted_signature','expected_binding','inventory_completeness','finding_reproduction')) {
        Require ($j.dimensions.$name.status -eq 'PASS') "Standalone M4 dimension failed: $name"
    }
    Complete-Step $v ([ordered]@{ mode = $j.mode; inspection_passed = $j.inspection_passed; fresh_submission = $j.fresh_submission; dimensions = $j.dimensions }) @((Join-Path $m4dir 'evidence.json'))

    $m5dir = Join-Path $run 'm5'
    Require (-not (Test-Path $m5dir)) 'M5 output directory already exists'
    $m5 = Invoke-Child 'M5-campaign' @('-B','-m','chainguard.m5','campaign','--directory',$m5dir)
    $j = Read-Json $m5.stdout_log
    $m5files = @('acceptance.sqlite','live\audit.sqlite','live\evidence.json','live\expected.json','live\configuration.json','live\fixture-private.pem','live\fixture-public.pem') | ForEach-Object { Join-Path $m5dir $_ }
    foreach ($file in $m5files) { Require (Test-Path $file -PathType Leaf) "M5 artifact missing: $file" }
    Require (Test-Path (Join-Path $m5dir 'synthetic') -PathType Container) 'M5 synthetic campaign artifact directory missing'
    Require ($j.passed -eq $true -and $j.fresh_acceptance.status -eq 'ACCEPTED' -and $j.duplicate_after_process_restart.status -eq 'REJECTED' -and $j.duplicate_after_process_restart.reason -eq 'ALREADY_ACCEPTED' -and $j.live_M4.offline_verification.inspection_passed -eq $true -and $j.operational_campaign.passed -eq $true) 'M5 acceptance, duplicate, or campaign result mismatch'
    Require (@($j.synthetic_campaign | Where-Object { $_.passed -ne $true }).Count -eq 0) 'M5 synthetic campaign has a failing case'
    $m5artifacts = @($m5files) + @((Join-Path $m5dir 'synthetic'))
    Complete-Step $m5 ([ordered]@{ first_submission = $j.fresh_acceptance.status; duplicate_status = $j.duplicate_after_process_restart.status; duplicate_reason = $j.duplicate_after_process_restart.reason; synthetic_cases = $j.synthetic_campaign.Count; engineering_tests = $j.operational_campaign.tests_run; passed = $j.passed }) $m5artifacts
    $manifest.artifacts.m5 = $m5artifacts

    Write-Host "`n=== M6Q-retained-inspection ==="
    $m6step = [ordered]@{ name = 'M6Q-retained-inspection'; status = 'RUNNING'; command = @();
        started_utc = (Get-Date).ToUniversalTime().ToString('o'); ended_utc = $null; exit_code = $null;
        stdout_log = $null; stderr_log = $null; artifacts = @($requiredHistorical | ForEach-Object { Join-Path $historical $_ }); verification = [ordered]@{} }
    $manifest.steps += $m6step; Save-Manifest
    $cases = Read-Json (Join-Path $historical 'case_results.json')
    $offline = Read-Json (Join-Path $historical 'offline_verification.json')
    $fresh = Read-Json (Join-Path $historical 'fresh_process_reinspection.json')
    $readback = Read-Json (Join-Path $historical 'fresh_submission_readback.json')
    $ids = @($cases.cases.PSObject.Properties.Name)
    Require ($ids.Count -eq 8 -and @($ids | Where-Object { $cases.cases.$_.status -ne 'PASSED' }).Count -eq 0) 'Retained M6Q case status is incomplete'
    foreach ($id in $ids) { Require (@($cases.cases.$id.checks | Where-Object { $_.passed -ne $true }).Count -eq 0) "Retained M6Q case check failed: $id" }
    Require ($offline.inspection_passed -eq $true -and $fresh.inspection_passed -eq $true -and $readback.post_restart_state -eq 'ACCEPTED' -and $readback.duplicate_after_restart.reason -eq 'ALREADY_ACCEPTED') 'Retained M6Q inspection/readback status differs from expected historical evidence'
    foreach ($report in @($offline, $fresh)) {
        foreach ($dimension in $report.dimensions.PSObject.Properties) { Require ($dimension.Value.status -eq 'PASS') "Retained M6Q dimension failed: $($dimension.Name)" }
    }
    $m6step.verification = [ordered]@{ classification = 'retained engineering qualification, not research evaluation'; case_ids = $ids;
        offline_inspection_passed = $offline.inspection_passed; fresh_process_reinspection_passed = $fresh.inspection_passed;
        post_restart_state = $readback.post_restart_state; duplicate_reason = $readback.duplicate_after_restart.reason }
    $m6step.exit_code = 0; $m6step.status = 'PASSED'; $m6step.ended_utc = (Get-Date).ToUniversalTime().ToString('o')
    Save-Manifest
    Write-Host ('Retained M6Q: ' + ($m6step.verification | ConvertTo-Json -Compress -Depth 5))
    Write-Host 'Historical harness was not run; historical files were only read.'

    $manifest.status = 'PASSED'
    Write-Host "`nSuite passed. Preserve the entire output directory: $run"
} catch {
    $manifest.status = 'FAILED'
    $manifest.failed_step = if ($manifest.steps.Count) { $manifest.steps[-1].name } else { 'preflight' }
    if ($manifest.steps.Count -and $manifest.steps[-1].status -ne 'PASSED') {
        $manifest.steps[-1].status = 'FAILED'
        $manifest.steps[-1].ended_utc = (Get-Date).ToUniversalTime().ToString('o')
    }
    Write-Error -Message ("Professor demonstration stopped at {0}: {1}. Evidence is retained at {2}" -f $manifest.failed_step, $_.Exception.Message, $run) -ErrorAction Continue
    exit 1
} finally {
    $manifest.ended_utc = (Get-Date).ToUniversalTime().ToString('o')
    Save-Manifest
    if ($null -ne $run) { Write-Host ('Run manifest: ' + (Join-Path $run 'run-manifest.json')) }
}
