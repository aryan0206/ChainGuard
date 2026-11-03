$ErrorActionPreference = 'Stop'
$here = (Resolve-Path $PSScriptRoot).Path
$runs = @(Get-ChildItem -LiteralPath $here -Filter '*.run.json' -File | Sort-Object Name | ForEach-Object {
    $record = Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json
    [ordered]@{metadata_file=$_.Name; record=$record}
})
$start = [datetimeoffset]::Parse('2026-11-03T12:41:44+05:30')
$end = [datetimeoffset](Get-Date)
[ordered]@{
    schema='chainguard-five-hour-execution-log-v1'
    model_tool='GPT-6 Codex desktop; PowerShell 7.6.5; CPython 3.14.3; official GitHub web and read-only connector for approved reference source'
    start_local=$start.ToString('o')
    end_local=$end.ToString('o')
    elapsed_seconds=[math]::Round(($end - $start).TotalSeconds,3)
    maximum_seconds=18000
    token_usage='NOT EXPOSED'
    generation_time='NOT EXPOSED'
    owner_revision='89dfbf78a953701cad2eb17da03218ff2abec709'
    source_snapshot='current_source_and_owner_pin.json'
    commands_and_exit_codes=$runs
    results=@('Current-source M6Q 8/8 passed; separate fresh reinspection and acceptance passed',
      'E03 bounded synthetic pilot 5 frozen calls, 4 detector-evaluable cases, 2 parents; one schema-rejected control excluded',
      'E08 R02 reference subset conformance 10/10 passed; no comparative research',
      'E09 A3 development mutant expectations 3/5 matched; two mismatches retained',
      'E10 signed-wrong development four cases matched; no research result',
      'E12 15 one-shot development measurements; no research benchmark',
      'E01/E13 three development metamorphic pairs; no research result')
    failures_and_retries=@('Sandbox Python launch denied before E03 run (e03_pilot.run.json, exit 101); escalated retry exit 0',
      'Initial E13 development invariant expectation failed on legitimate B1 input-count change; revised expectation exit 0',
      'Initial E12 Windows working-set sampling returned null; WinAPI signature corrected and second development run exit 0',
      'E09 first launcher missing PYTHONPATH; retry lacked trusted pin; pinned retry exit 1 with two genuine dimension mismatches')
    boundaries=@('No Git commands or repository Git operations','No dependency installation','No architecture/protocol or A1/A2/E08 pin change',
      'No IEEE report writing/compilation','No audit.sqlite in deliverables','Earlier evidence preserved')
} | ConvertTo-Json -Depth 18 | Set-Content -LiteralPath (Join-Path $here 'execution_log.json') -Encoding utf8
