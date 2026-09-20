[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$SubscriptionId,
    [string]$ResourceGroup = "rg-entra-behavior-guard",
    [string]$Location = "eastus2",
    [string]$Prefix = "ebg",
    [int]$BakeInDays = 14,
    [int]$MinBaselineEvents = 25,
    [int]$AlertScoreThreshold = 45,
    [int]$EnforcementScoreThreshold = 80,
    [ValidateSet("revokeSessions","disableAndRevoke")][string]$EnforcementAction = "revokeSessions",
    [switch]$EnableBetaNonInteractive,
    [string]$ProtectedUpns = "",
    [switch]$GrantDisablePermission,
    [switch]$SkipCodeDeployment
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
if ($EnforcementAction -eq "disableAndRevoke" -and -not $GrantDisablePermission) {
    throw "-EnforcementAction disableAndRevoke requires -GrantDisablePermission. Enforcement is still deployed OFF, but the permission set must match the intended action."
}

function Invoke-AzJson {
    param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Args)
    $raw = & az @Args --only-show-errors -o json
    if ($LASTEXITCODE -ne 0) { throw "Azure CLI command failed: az $($Args -join ' ')" }
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    return $raw | ConvertFrom-Json
}

function Invoke-Az {
    param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Args)
    & az @Args --only-show-errors
    if ($LASTEXITCODE -ne 0) { throw "Azure CLI command failed: az $($Args -join ' ')" }
}

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw "Azure CLI is required. Install Azure CLI, then run 'az login' before this installer."
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$srcDir = Join-Path $repoRoot "src"
$bicep = Join-Path $repoRoot "infra/main.bicep"

Write-Host "[1/9] Selecting subscription..." -ForegroundColor Cyan
Invoke-Az account set --subscription $SubscriptionId
$account = Invoke-AzJson account show
$tenantId = $account.tenantId

Write-Host "[2/9] Creating resource group and Azure infrastructure..." -ForegroundColor Cyan
Invoke-Az group create --name $ResourceGroup --location $Location | Out-Null
$deploymentName = "entra-behavior-guard-$(Get-Date -Format yyyyMMddHHmmss)"
$deployment = Invoke-AzJson deployment group create `
    --resource-group $ResourceGroup `
    --name $deploymentName `
    --template-file $bicep `
    --parameters prefix=$Prefix bakeInDays=$BakeInDays minBaselineEvents=$MinBaselineEvents `
        alertScoreThreshold=$AlertScoreThreshold enforcementScoreThreshold=$EnforcementScoreThreshold `
        enforcementEnabled=false enforcementAction=$EnforcementAction `
        enableBetaNonInteractive=$($EnableBetaNonInteractive.IsPresent.ToString().ToLower()) `
        protectedUpns=$ProtectedUpns

$out = $deployment.properties.outputs
$functionAppName = $out.functionAppName.value
$keyVaultName = $out.keyVaultName.value
$keyVaultId = $out.keyVaultId.value
$dataStorageName = $out.dataStorageName.value

Write-Host "[3/9] Creating Entra application registration and service principal..." -ForegroundColor Cyan
$appDisplayName = "Entra Behavior Guard ($Prefix)"
$existing = Invoke-AzJson ad app list --display-name $appDisplayName
if ($existing.Count -gt 0) {
    $appDisplayName = "$appDisplayName $(Get-Date -Format yyyyMMdd-HHmmss)"
    Write-Warning "An app registration with the base name already exists. Creating a new registration named '$appDisplayName' rather than modifying the existing app."
}
$app = Invoke-AzJson ad app create --display-name $appDisplayName --sign-in-audience AzureADMyOrg
$appId = $app.appId
$appObjectId = $app.id

$sp = $null
try { $sp = Invoke-AzJson ad sp show --id $appId } catch { }
if (-not $sp) {
    $sp = Invoke-AzJson ad sp create --id $appId
}
$appSpId = $sp.id

Write-Host "[4/9] Declaring and granting Microsoft Graph application permissions..." -ForegroundColor Cyan
$graphAppId = "00000003-0000-0000-c000-000000000000"
$graphSp = Invoke-AzJson ad sp show --id $graphAppId
$permissionValues = @("AuditLog.Read.All", "User.RevokeSessions.All")
if ($GrantDisablePermission) {
    $permissionValues += @("User.EnableDisableAccount.All", "User.Read.All")
}

$roles = @()
foreach ($value in $permissionValues) {
    $role = $graphSp.appRoles | Where-Object { $_.value -eq $value -and $_.allowedMemberTypes -contains "Application" } | Select-Object -First 1
    if (-not $role) { throw "Could not resolve Microsoft Graph application role: $value" }
    $roles += $role
}

$requiredResourceAccess = @(
    @{
        resourceAppId = $graphAppId
        resourceAccess = @($roles | ForEach-Object { @{ id = $_.id; type = "Role" } })
    }
)
$patchBody = @{ requiredResourceAccess = $requiredResourceAccess } | ConvertTo-Json -Depth 8 -Compress
Invoke-Az rest --method PATCH --uri "https://graph.microsoft.com/v1.0/applications/$appObjectId" --headers "Content-Type=application/json" --body $patchBody | Out-Null

$existingAssignments = Invoke-AzJson rest --method GET --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$appSpId/appRoleAssignments"
foreach ($role in $roles) {
    $already = $existingAssignments.value | Where-Object { $_.resourceId -eq $graphSp.id -and $_.appRoleId -eq $role.id }
    if (-not $already) {
        $body = @{ principalId = $appSpId; resourceId = $graphSp.id; appRoleId = $role.id } | ConvertTo-Json -Compress
        try {
            Invoke-Az rest --method POST --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$appSpId/appRoleAssignments" --headers "Content-Type=application/json" --body $body | Out-Null
        } catch {
            throw "Failed to grant $($role.value). The installer identity generally needs a sufficiently privileged Entra role (for example Privileged Role Administrator / Global Administrator) and Graph authorization to grant application permissions. $($_.Exception.Message)"
        }
    }
}

Write-Host "[5/9] Creating certificate credential directly in Azure Key Vault..." -ForegroundColor Cyan
$currentUserObjectId = $null
try { $currentUserObjectId = (& az ad signed-in-user show --query id -o tsv --only-show-errors).Trim() } catch { }
$tempKvRoleCreated = $false
if ($currentUserObjectId) {
    try {
        Invoke-Az role assignment create --assignee-object-id $currentUserObjectId --assignee-principal-type User --role "Key Vault Certificates Officer" --scope $keyVaultId | Out-Null
        $tempKvRoleCreated = $true
        Start-Sleep -Seconds 10
    } catch {
        Write-Warning "Could not grant temporary Key Vault Certificates Officer role automatically. Certificate creation may fail unless you already have Key Vault data-plane permission."
    }
}

$certName = "entra-behavior-guard-auth"
try {
    $certCreated = $false
    for ($i = 1; $i -le 6 -and -not $certCreated; $i++) {
        try {
            Invoke-Az ad app credential reset --id $appId --create-cert --keyvault $keyVaultName --cert $certName --append --years 2 | Out-Null
            $certCreated = $true
        } catch {
            if ($i -eq 6) { throw }
            Write-Warning "Certificate creation not ready yet (often RBAC propagation). Retrying..."
            Start-Sleep -Seconds 10
        }
    }
} finally {
    if ($tempKvRoleCreated) {
        try { Invoke-Az role assignment delete --assignee-object-id $currentUserObjectId --role "Key Vault Certificates Officer" --scope $keyVaultId | Out-Null } catch { }
    }
}

Write-Host "[6/9] Configuring Function App with tenant/app identity..." -ForegroundColor Cyan
Invoke-Az functionapp config appsettings set --resource-group $ResourceGroup --name $functionAppName --settings `
    "TENANT_ID=$tenantId" `
    "GRAPH_CLIENT_ID=$appId" `
    "GRAPH_CERT_SECRET_NAME=$certName" `
    "ENFORCEMENT_ENABLED=false" | Out-Null

if (-not $SkipCodeDeployment) {
    Write-Host "[7/9] Packaging and deploying Function code (remote build)..." -ForegroundColor Cyan
    $zipPath = Join-Path ([System.IO.Path]::GetTempPath()) "entra-behavior-guard-function.zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    Compress-Archive -Path (Join-Path $srcDir "*") -DestinationPath $zipPath -Force
    Invoke-Az functionapp deployment source config-zip --resource-group $ResourceGroup --name $functionAppName --src $zipPath --build-remote true | Out-Null
} else {
    Write-Host "[7/9] Code deployment skipped by request." -ForegroundColor Yellow
}

Write-Host "[8/9] Writing local deployment metadata..." -ForegroundColor Cyan
$metadata = [ordered]@{
    installedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
    subscriptionId = $SubscriptionId
    tenantId = $tenantId
    resourceGroup = $ResourceGroup
    functionAppName = $functionAppName
    keyVaultName = $keyVaultName
    dataStorageName = $dataStorageName
    appDisplayName = $appDisplayName
    appId = $appId
    appObjectId = $appObjectId
    servicePrincipalObjectId = $appSpId
    bakeInDays = $BakeInDays
    enforcementEnabled = $false
    enforcementAction = $EnforcementAction
    graphPermissions = $permissionValues
}
$metadata | ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $repoRoot "deployment.json") -Encoding utf8

Write-Host "[9/9] Complete." -ForegroundColor Green
Write-Host "Function App: $functionAppName"
Write-Host "App registration: $appDisplayName ($appId)"
Write-Host "Data storage: $dataStorageName"
Write-Host "Enforcement is OFF. Allow at least $BakeInDays days plus $MinBaselineEvents successful events/user before considering enforcement."
Write-Host "Use installer/Set-Enforcement.ps1 only after reviewing alerts and adding protected/break-glass accounts."
if (-not $GrantDisablePermission) {
    Write-Host "Account-disable permission was NOT granted. Revoke-session enforcement is available; re-run with -GrantDisablePermission if you intentionally want disableAndRevoke." -ForegroundColor Yellow
}
