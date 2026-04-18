param(
    [string]$Dataset = "Blade+Runner+-+train.zip",
    [string]$Output = "submission_bladerunner_best.txt",
    [string]$Report = "report_bladerunner_best.json",
    [double]$Threshold = 5.0,
    [int]$LlmTopN = 8,
    [switch]$Offline
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-LangfuseSessionId {
    $traceOutput = py -3 trace_session.py 2>&1
    $traceText = ($traceOutput | Out-String).Trim()
    if ($traceText) {
        Write-Host $traceText
    }

    $match = [regex]::Match($traceText, "Langfuse session id:\s*(.+)")
    if (-not $match.Success) {
        throw "Unable to parse Langfuse session id from trace_session.py output."
    }

    return $match.Groups[1].Value.Trim()
}

function Show-RunSummary {
    param(
        [string]$ReportPath,
        [string]$SubmissionPath,
        [string]$SessionId,
        [bool]$UsedLlmJudge
    )

    $reportJson = Get-Content $ReportPath -Raw | ConvertFrom-Json
    Write-Host ""
    Write-Host ("Selected transactions: {0}" -f $reportJson.selected_count)
    Write-Host ("Submission file: {0}" -f (Resolve-Path $SubmissionPath))
    Write-Host ("Report file: {0}" -f (Resolve-Path $ReportPath))
    if ($UsedLlmJudge) {
        Write-Host ("Langfuse session id: {0}" -f $SessionId)
    }
}

$sessionId = $null
$mainArgs = @(
    "main.py",
    "--dataset", $Dataset,
    "--output", $Output,
    "--report", $Report,
    "--threshold", $Threshold,
    "--llm-top-n", $LlmTopN
)

if (-not $Offline) {
    $sessionId = Get-LangfuseSessionId
    $mainArgs += @("--use-llm-judge", "--session-id", $sessionId)
}

& py -3 @mainArgs
Show-RunSummary -ReportPath $Report -SubmissionPath $Output -SessionId $sessionId -UsedLlmJudge (-not $Offline)
