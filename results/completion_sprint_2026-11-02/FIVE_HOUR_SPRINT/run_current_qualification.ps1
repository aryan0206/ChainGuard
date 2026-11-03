param([Parameter(Mandatory=$true)][string]$TrustedRevision)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$root = (Resolve-Path (Join-Path $here '..\..\..')).Path
$python = (Resolve-Path (Join-Path $root '.venv\Scripts\python.exe')).Path
if ($TrustedRevision -notmatch '^[0-9a-f]{40}$' -or
    $TrustedRevision -eq '8b27b5a980a87887be66c409c5a6a31d415a3326') {
    throw 'A new owner-attested lowercase 40-hex revision is required'
}
$prior = Get-Content -Raw (Join-Path $here '..\RESEARCH_UNBLOCKING\focused_current_retry.run.json') | ConvertFrom-Json
$hashes = [ordered]@{}
foreach ($property in $prior.source_sha256.PSObject.Properties) {
    $path = Join-Path $root $property.Name
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $property.Value) { throw "Current app source differs from focused-test snapshot: $($property.Name)" }
    $hashes[$property.Name] = $actual
}
$outDir = Join-Path $here 'live_m6_current'
$meta = Join-Path $here 'current_qualification.run.json'
$snapshot = Join-Path $here 'current_source_and_owner_pin.json'
if ((Test-Path $outDir) -or (Test-Path $meta) -or (Test-Path $snapshot)) { throw 'Qualification evidence already exists' }
$env:CHAINGUARD_ASSESSOR_REVISION_PIN = $TrustedRevision
$env:CHAINGUARD_TRUSTED_CODE_REVISION = $TrustedRevision
$env:PYTHONPATH = $root
[ordered]@{
    owner_supplied_pin = $TrustedRevision
    trust_basis = 'Owner supplied this value in response to request to attest exact current application source on 3 November 2026; no agent Git command or independent commit checkout'
    prior_engineering_source_snapshot = '..\RESEARCH_UNBLOCKING\focused_current_retry.run.json'
    source_sha256_rechecked = $hashes
    checked_local = (Get-Date).ToString('o')
    limitation = 'Hash equality with focused-test files plus owner attestation, not agent-verifiable repository ancestry'
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $snapshot -Encoding utf8
$steps = @(
    @{label='current_m6q';script='qualify_live_current.py'},
    @{label='current_reinspect';script='reinspect_current.py'},
    @{label='current_fresh_submission';script='submit_current.py'}
)
$records = @()
foreach ($step in $steps) {
    $out = Join-Path $here "$($step.label).stdout.log"
    $err = Join-Path $here "$($step.label).stderr.log"
    if ((Test-Path $out) -or (Test-Path $err)) { throw "Existing log for $($step.label)" }
    $relative = "results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/$($step.script)"
    $start = Get-Date
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $process = Start-Process -FilePath $python -ArgumentList @('-B',$relative) -WorkingDirectory $root `
        -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
    $timer.Stop()
    $records += [ordered]@{
        command = ".\.venv\Scripts\python.exe -B $relative"
        start_local = $start.ToString('o')
        end_local = (Get-Date).ToString('o')
        elapsed_seconds = $timer.Elapsed.TotalSeconds
        exit_code = $process.ExitCode
        stdout = $out
        stderr = $err
    }
    if ($process.ExitCode -ne 0) { break }
}
[ordered]@{
    owner_pin = $TrustedRevision
    synthetic_pin = $false
    source_snapshot = $snapshot
    python_version = (& $python --version 2>&1 | Out-String).Trim()
    powershell_version = $PSVersionTable.PSVersion.ToString()
    os = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
    steps = $records
} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $meta -Encoding utf8
exit $records[-1].exit_code
