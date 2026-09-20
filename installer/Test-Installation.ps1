[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$DeploymentJson = (Join-Path (Split-Path -Parent $PSScriptRoot) "deployment.json"))
$ErrorActionPreference = "Stop"
$d = Get-Content $DeploymentJson -Raw | ConvertFrom-Json
Write-Host "Checking Function App..." -ForegroundColor Cyan
az functionapp show -g $d.resourceGroup -n $d.functionAppName --only-show-errors -o table
Write-Host "Checking app certificate credentials..." -ForegroundColor Cyan
az ad app credential list --id $d.appId --cert --only-show-errors -o table
Write-Host "Checking Graph application role assignments..." -ForegroundColor Cyan
az rest --method GET --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($d.servicePrincipalObjectId)/appRoleAssignments" --only-show-errors -o jsonc
Write-Host "Checking Function settings (values redacted by CLI where applicable)..." -ForegroundColor Cyan
az functionapp config appsettings list -g $d.resourceGroup -n $d.functionAppName --query "[?name=='ENFORCEMENT_ENABLED' || name=='BAKE_IN_DAYS' || name=='GRAPH_CLIENT_ID' || name=='ENABLE_BETA_NONINTERACTIVE'].{name:name,value:value}" -o table
