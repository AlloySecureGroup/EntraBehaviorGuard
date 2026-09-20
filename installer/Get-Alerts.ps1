[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$StorageAccount,
    [string]$Container = "behavior-guard",
    [string]$Destination = (Join-Path $PWD "EntraBehaviorGuard-Alerts")
)
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Path $Destination -Force | Out-Null
az storage blob download-batch --account-name $StorageAccount --source $Container --destination $Destination --pattern "alerts/*" --auth-mode login --only-show-errors
if ($LASTEXITCODE -ne 0) { throw "Failed to download alerts. Your identity needs Storage Blob Data Reader (or higher) on the data storage account." }
Write-Host "Downloaded alerts to $Destination" -ForegroundColor Green
