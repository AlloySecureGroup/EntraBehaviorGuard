[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)][string]$ResourceGroup,
    [Parameter(Mandatory=$true)][string]$FunctionAppName,
    [Parameter(Mandatory=$true)][bool]$Enabled,
    [ValidateSet("revokeSessions","disableAndRevoke")][string]$Action = "revokeSessions",
    [ValidateRange(1,100)][int]$ScoreThreshold = 80,
    [ValidateRange(1,20)][int]$MaxActionsPerRun = 3,
    [string]$ProtectedUpns = "",
    [string]$ProtectedUserIds = ""
)
$ErrorActionPreference = "Stop"
if ($Enabled -and [string]::IsNullOrWhiteSpace($ProtectedUpns) -and [string]::IsNullOrWhiteSpace($ProtectedUserIds)) {
    throw "Refusing to enable enforcement without at least one protected user/UPN. Add emergency/break-glass accounts to the exclusion list."
}
if ($PSCmdlet.ShouldProcess($FunctionAppName, "Set Entra Behavior Guard enforcement to $Enabled / $Action")) {
    az functionapp config appsettings set --resource-group $ResourceGroup --name $FunctionAppName --settings `
        "ENFORCEMENT_ENABLED=$($Enabled.ToString().ToLower())" `
        "ENFORCEMENT_ACTION=$Action" `
        "ENFORCEMENT_SCORE_THRESHOLD=$ScoreThreshold" `
        "MAX_ENFORCEMENT_ACTIONS_PER_RUN=$MaxActionsPerRun" `
        "PROTECTED_UPNS=$ProtectedUpns" `
        "PROTECTED_USER_IDS=$ProtectedUserIds" --only-show-errors | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to update Function App settings." }
    Write-Host "Enforcement updated. Enabled=$Enabled Action=$Action Threshold=$ScoreThreshold MaxActionsPerRun=$MaxActionsPerRun" -ForegroundColor Green
}
