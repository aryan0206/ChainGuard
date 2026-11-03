param([Parameter(Mandatory=$true)][string]$Script,
      [Parameter(Mandatory=$true)][string]$Label,
      [string]$TrustedRevision = '')
$ErrorActionPreference = 'Stop'
$here = (Resolve-Path $PSScriptRoot).Path
$root = (Resolve-Path (Join-Path $here '..\..\..')).Path
$scriptPath = (Resolve-Path (Join-Path $here $Script)).Path
if (-not $scriptPath.StartsWith($here + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Script must be within FIVE_HOUR_SPRINT'
}
if ($Label -notmatch '^[a-z0-9_]+$') { throw 'Invalid evidence label' }
$python = (Resolve-Path (Join-Path $root '.venv\Scripts\python.exe')).Path
$env:PYTHONPATH = $root
if ($TrustedRevision) {
    if ($TrustedRevision -notmatch '^[0-9a-f]{40}$') { throw 'Invalid trusted revision' }
    $env:CHAINGUARD_ASSESSOR_REVISION_PIN = $TrustedRevision
    $env:CHAINGUARD_TRUSTED_CODE_REVISION = $TrustedRevision
}
$relative = [IO.Path]::GetRelativePath($root, $scriptPath).Replace('\','/')
$out = Join-Path $here "$Label.stdout.log"
$err = Join-Path $here "$Label.stderr.log"
$meta = Join-Path $here "$Label.run.json"
if ((Test-Path $out) -or (Test-Path $err) -or (Test-Path $meta)) { throw 'Evidence already exists' }
$start = Get-Date
$timer = [Diagnostics.Stopwatch]::StartNew()
$process = Start-Process -FilePath $python -ArgumentList @('-B',$relative) -WorkingDirectory $root `
    -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
$timer.Stop()
[ordered]@{command=".\.venv\Scripts\python.exe -B $relative";
    trusted_revision = $(if ($TrustedRevision) { $TrustedRevision } else { 'NOT_SET' });
    start_local=$start.ToString('o');end_local=(Get-Date).ToString('o');
    elapsed_seconds=$timer.Elapsed.TotalSeconds;exit_code=$process.ExitCode;
    python_version=(& $python --version 2>&1 | Out-String).Trim();
    powershell_version=$PSVersionTable.PSVersion.ToString();stdout=$out;stderr=$err} |
    ConvertTo-Json | Set-Content -LiteralPath $meta -Encoding utf8
exit $process.ExitCode
