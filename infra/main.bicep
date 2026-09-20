@description('Short lowercase deployment prefix, letters/numbers only recommended.')
param prefix string = 'ebg'

@description('Azure region.')
param location string = resourceGroup().location

@description('Bake-in period in days.')
param bakeInDays int = 14

@description('Minimum successful user sign-ins before the baseline is considered mature.')
param minBaselineEvents int = 25

@description('Alert score threshold from 0-100.')
param alertScoreThreshold int = 45

@description('Enforcement score threshold from 0-100.')
param enforcementScoreThreshold int = 80

@description('Enforcement enabled at deployment. Keep false until bake-in is complete and alerts are tuned.')
param enforcementEnabled bool = false

@allowed([
  'revokeSessions'
  'disableAndRevoke'
])
param enforcementAction string = 'revokeSessions'

@description('Optional beta sign-in API mode to include non-interactive user sign-ins. Beta APIs are not supported for production by Microsoft.')
param enableBetaNonInteractive bool = false

@description('Comma-separated protected UPNs; always exclude emergency/break-glass accounts.')
param protectedUpns string = ''

var suffix = uniqueString(subscription().id, resourceGroup().id, prefix)
var safePrefix = toLower(replace(replace(prefix, '-', ''), '_', ''))
var hostStorageName = take('${safePrefix}host${suffix}', 24)
var dataStorageName = take('${safePrefix}data${suffix}', 24)
var planName = '${prefix}-plan-${take(suffix, 6)}'
var functionName = '${prefix}-func-${take(suffix, 8)}'
var kvName = take('${prefix}-kv-${take(suffix, 8)}', 24)
var aiName = '${prefix}-ai-${take(suffix, 8)}'
var containerName = 'behavior-guard'

resource hostStorage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: hostStorageName
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
  }
}

resource dataStorage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: dataStorageName
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Allow'
    }
    encryption: {
      keySource: 'Microsoft.Storage'
      services: {
        blob: { enabled: true }
        file: { enabled: true }
      }
    }
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: dataStorage
  name: 'default'
  properties: {
    deleteRetentionPolicy: { enabled: true, days: 14 }
    containerDeleteRetentionPolicy: { enabled: true, days: 14 }
    isVersioningEnabled: true
  }
}

resource dataContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: containerName
  properties: { publicAccess: 'None' }
}

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: kvName
  location: location
  properties: {
    tenantId: tenant().tenantId
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 14
    enablePurgeProtection: false
    publicNetworkAccess: 'Enabled'
    sku: { family: 'A', name: 'standard' }
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: aiName
  location: location
  kind: 'web'
  properties: { Application_Type: 'web' }
}

resource hostingPlan 'Microsoft.Web/serverfarms@2024-04-01' = {
  name: planName
  location: location
  kind: 'linux'
  sku: { name: 'Y1', tier: 'Dynamic' }
  properties: { reserved: true }
}

resource functionApp 'Microsoft.Web/sites@2024-04-01' = {
  name: functionName
  location: location
  kind: 'functionapp,linux'
  identity: { type: 'SystemAssigned' }
  properties: {
    httpsOnly: true
    serverFarmId: hostingPlan.id
    siteConfig: {
      linuxFxVersion: 'Python|3.11'
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      http20Enabled: true
      appSettings: [
        { name: 'FUNCTIONS_EXTENSION_VERSION', value: '~4' }
        { name: 'FUNCTIONS_WORKER_RUNTIME', value: 'python' }
        { name: 'AzureWebJobsStorage', value: 'DefaultEndpointsProtocol=https;AccountName=${hostStorage.name};EndpointSuffix=${environment().suffixes.storage};AccountKey=${hostStorage.listKeys().keys[0].value}' }
        { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: appInsights.properties.ConnectionString }
        { name: 'DATA_STORAGE_BLOB_URL', value: 'https://${dataStorage.name}.blob.${environment().suffixes.storage}' }
        { name: 'DATA_CONTAINER', value: containerName }
        { name: 'KEY_VAULT_URL', value: keyVault.properties.vaultUri }
        { name: 'GRAPH_CERT_SECRET_NAME', value: 'entra-behavior-guard-auth' }
        { name: 'TENANT_ID', value: tenant().tenantId }
        { name: 'GRAPH_CLIENT_ID', value: 'SET-BY-INSTALLER' }
        { name: 'BAKE_IN_DAYS', value: string(bakeInDays) }
        { name: 'MIN_BASELINE_EVENTS', value: string(minBaselineEvents) }
        { name: 'MIN_OAUTH_BASELINE_EVENTS', value: '3' }
        { name: 'ALERT_SCORE_THRESHOLD', value: string(alertScoreThreshold) }
        { name: 'ENFORCEMENT_ENABLED', value: string(enforcementEnabled) }
        { name: 'ENFORCEMENT_SCORE_THRESHOLD', value: string(enforcementScoreThreshold) }
        { name: 'ENFORCEMENT_ACTION', value: enforcementAction }
        { name: 'MAX_ENFORCEMENT_ACTIONS_PER_RUN', value: '3' }
        { name: 'ENABLE_BETA_NONINTERACTIVE', value: string(enableBetaNonInteractive) }
        { name: 'PROTECTED_UPNS', value: protectedUpns }
        { name: 'PROTECTED_USER_IDS', value: '' }
        { name: 'TIMER_SCHEDULE', value: '0 */5 * * * *' }
        { name: 'QUERY_OVERLAP_MINUTES', value: '5' }
        { name: 'INITIAL_LOOKBACK_MINUTES', value: '60' }
        { name: 'SCM_DO_BUILD_DURING_DEPLOYMENT', value: 'true' }
        { name: 'ENABLE_ORYX_BUILD', value: 'true' }
      ]
    }
  }
}

var storageBlobContributor = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
var keyVaultSecretsUser = '4633458b-17de-408a-b874-0445c86b69e6'

resource dataStorageRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(dataStorage.id, functionApp.id, storageBlobContributor)
  scope: dataStorage
  properties: {
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageBlobContributor)
  }
}

resource kvSecretsRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, functionApp.id, keyVaultSecretsUser)
  scope: keyVault
  properties: {
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', keyVaultSecretsUser)
  }
}

output functionAppName string = functionApp.name
output functionPrincipalId string = functionApp.identity.principalId
output keyVaultName string = keyVault.name
output keyVaultId string = keyVault.id
output dataStorageName string = dataStorage.name
output dataStorageId string = dataStorage.id
output containerName string = containerName
output tenantId string = tenant().tenantId
