[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter(Mandatory=$true)][string]$DeploymentJson,
    [switch]$DeleteAppRegistration
)
$ErrorActionPreference = "Stop"
$d = Get-Content $DeploymentJson -Raw | ConvertFrom-Json
if ($PSCmdlet.ShouldProcess($d.resourceGroup, "Delete Entra Behavior Guard Azure resource group")) {
    az group delete --name $d.resourceGroup --yes --no-wait --only-show-errors
}
if ($DeleteAppRegistration -and $PSCmdlet.ShouldProcess($d.appId, "Delete Entra app registration")) {
    az ad app delete --id $d.appId --only-show-errors
}
Write-Host "Deletion submitted. Key Vault soft-delete can retain deleted vault/certificate metadata for the configured retention period." -ForegroundColor Yellow
