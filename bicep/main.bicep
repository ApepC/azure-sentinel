// ============================================================
// Azure Sentinel Infrastructure — Main Deployment
// AZ-104 Portfolio Project | Fred Mann
// ============================================================
// Deploys: VNet + Subnets, NSGs, Storage Account,
//          Key Vault, Log Analytics Workspace, VM (optional)
// ============================================================

targetScope = 'resourceGroup'

// ── Parameters ──────────────────────────────────────────────
@description('Environment name: dev, staging, prod')
@allowed(['dev', 'staging', 'prod'])
param environment string = 'dev'

@description('Azure region for all resources')
param location string = resourceGroup().location

@description('Project name used as resource prefix')
@maxLength(8)
param projectName string = 'sentinel'

@description('Your IP address for NSG allow-list (e.g. 203.0.113.0/32)')
param allowedAdminCidr string

@description('Deploy a demo Linux VM?')
param deployVM bool = false

@description('Admin username for VM')
param adminUsername string = 'azureadmin'

@secure()
@description('Admin password for VM (if deployVM = true)')
param adminPassword string = ''

@description('Tags applied to all resources')
param tags object = {
  project: 'az104-portfolio'
  environment: environment
  managedBy: 'bicep'
  owner: 'fred-mann'
}

// ── Variables ────────────────────────────────────────────────
var prefix = '${projectName}-${environment}'
var vnetAddressSpace = '10.0.0.0/16'

var subnets = [
  { name: 'snet-frontend',   prefix: '10.0.1.0/24' }
  { name: 'snet-backend',    prefix: '10.0.2.0/24' }
  { name: 'snet-data',       prefix: '10.0.3.0/24' }
  { name: 'snet-management', prefix: '10.0.4.0/24' }
  { name: 'AzureBastionSubnet', prefix: '10.0.5.0/26' }  // Required name for Bastion
]

// ── Log Analytics Workspace ──────────────────────────────────
resource logWorkspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: 'law-${prefix}'
  location: location
  tags: tags
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

// ── Network Security Groups ──────────────────────────────────
resource nsgFrontend 'Microsoft.Network/networkSecurityGroups@2023-04-01' = {
  name: 'nsg-frontend-${prefix}'
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'Allow-HTTPS-Inbound'
        properties: {
          priority: 100
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: 'Internet'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '443'
          description: 'Allow HTTPS from internet'
        }
      }
      {
        name: 'Allow-HTTP-Inbound'
        properties: {
          priority: 110
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: 'Internet'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '80'
          description: 'Allow HTTP - redirect to HTTPS at app layer'
        }
      }
      {
        name: 'Deny-All-Other-Inbound'
        properties: {
          priority: 4096
          protocol: '*'
          access: 'Deny'
          direction: 'Inbound'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
          description: 'Default deny all other inbound'
        }
      }
    ]
  }
}

resource nsgBackend 'Microsoft.Network/networkSecurityGroups@2023-04-01' = {
  name: 'nsg-backend-${prefix}'
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'Allow-Frontend-To-Backend'
        properties: {
          priority: 100
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: '10.0.1.0/24'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '8080'
          description: 'Allow frontend subnet to reach backend API'
        }
      }
      {
        name: 'Deny-Internet-Inbound'
        properties: {
          priority: 200
          protocol: '*'
          access: 'Deny'
          direction: 'Inbound'
          sourceAddressPrefix: 'Internet'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
          description: 'Block all direct internet access to backend'
        }
      }
    ]
  }
}

resource nsgData 'Microsoft.Network/networkSecurityGroups@2023-04-01' = {
  name: 'nsg-data-${prefix}'
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'Allow-Backend-To-Data'
        properties: {
          priority: 100
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: '10.0.2.0/24'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '1433'
          description: 'Allow backend subnet to reach SQL data layer'
        }
      }
      {
        name: 'Deny-All-Inbound'
        properties: {
          priority: 4096
          protocol: '*'
          access: 'Deny'
          direction: 'Inbound'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
          description: 'Strict deny all - data tier never exposed'
        }
      }
    ]
  }
}

resource nsgManagement 'Microsoft.Network/networkSecurityGroups@2023-04-01' = {
  name: 'nsg-mgmt-${prefix}'
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'Allow-Admin-SSH-RDP'
        properties: {
          priority: 100
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: allowedAdminCidr
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRanges: ['22', '3389']
          description: 'Allow SSH/RDP from admin IP only'
        }
      }
      {
        name: 'Deny-All-Other-Management'
        properties: {
          priority: 4096
          protocol: '*'
          access: 'Deny'
          direction: 'Inbound'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
    ]
  }
}

// ── Virtual Network ──────────────────────────────────────────
resource vnet 'Microsoft.Network/virtualNetworks@2023-04-01' = {
  name: 'vnet-${prefix}'
  location: location
  tags: tags
  properties: {
    addressSpace: { addressPrefixes: [vnetAddressSpace] }
    subnets: [
      {
        name: subnets[0].name
        properties: {
          addressPrefix: subnets[0].prefix
          networkSecurityGroup: { id: nsgFrontend.id }
          serviceEndpoints: [{ service: 'Microsoft.Storage' }]
        }
      }
      {
        name: subnets[1].name
        properties: {
          addressPrefix: subnets[1].prefix
          networkSecurityGroup: { id: nsgBackend.id }
          serviceEndpoints: [{ service: 'Microsoft.KeyVault' }]
        }
      }
      {
        name: subnets[2].name
        properties: {
          addressPrefix: subnets[2].prefix
          networkSecurityGroup: { id: nsgData.id }
          serviceEndpoints: [
            { service: 'Microsoft.Sql' }
            { service: 'Microsoft.Storage' }
          ]
        }
      }
      {
        name: subnets[3].name
        properties: {
          addressPrefix: subnets[3].prefix
          networkSecurityGroup: { id: nsgManagement.id }
        }
      }
      {
        name: subnets[4].name
        properties: {
          addressPrefix: subnets[4].prefix
          // Bastion subnet cannot have NSG
        }
      }
    ]
  }
}

// ── Storage Account ──────────────────────────────────────────
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'st${projectName}${environment}${uniqueString(resourceGroup().id)}'
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: { name: environment == 'prod' ? 'Standard_GRS' : 'Standard_LRS' }
  properties: {
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'AzureServices'
      virtualNetworkRules: [
        { id: '${vnet.id}/subnets/${subnets[0].name}' }
        { id: '${vnet.id}/subnets/${subnets[2].name}' }
      ]
    }
    encryption: {
      services: {
        blob: { enabled: true, keyType: 'Account' }
        file: { enabled: true, keyType: 'Account' }
      }
      keySource: 'Microsoft.Storage'
    }
  }
}

// Diagnostic settings → Log Analytics
resource storageDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'diag-storage-${prefix}'
  scope: storageAccount
  properties: {
    workspaceId: logWorkspace.id
    metrics: [
      { category: 'Transaction', enabled: true, retentionPolicy: { enabled: false, days: 0 } }
      { category: 'Capacity',    enabled: true, retentionPolicy: { enabled: false, days: 0 } }
    ]
  }
}

// ── Key Vault ────────────────────────────────────────────────
resource keyVault 'Microsoft.KeyVault/vaults@2023-02-01' = {
  name: 'kv-${prefix}-${uniqueString(resourceGroup().id)}'
  location: location
  tags: tags
  properties: {
    sku: { family: 'A', name: 'standard' }
    tenantId: subscription().tenantId
    enableRbacAuthorization: true         // RBAC over legacy access policies
    enableSoftDelete: true
    softDeleteRetentionInDays: environment == 'prod' ? 90 : 7
    enablePurgeProtection: environment == 'prod' ? true : null
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'AzureServices'
      virtualNetworkRules: [
        { id: '${vnet.id}/subnets/${subnets[1].name}' }
      ]
    }
  }
}

resource kvDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'diag-kv-${prefix}'
  scope: keyVault
  properties: {
    workspaceId: logWorkspace.id
    logs: [
      { category: 'AuditEvent',            enabled: true }
      { category: 'AzurePolicyEvaluationDetails', enabled: true }
    ]
    metrics: [
      { category: 'AllMetrics', enabled: true }
    ]
  }
}

// ── Optional VM ──────────────────────────────────────────────
module linuxVM 'modules/linux-vm.bicep' = if (deployVM) {
  name: 'deploy-vm'
  params: {
    prefix: prefix
    location: location
    tags: tags
    subnetId: '${vnet.id}/subnets/${subnets[3].name}'
    adminUsername: adminUsername
    adminPassword: adminPassword
    logWorkspaceId: logWorkspace.id
    logWorkspaceKey: logWorkspace.listKeys().primarySharedKey
  }
}

// ── Outputs ──────────────────────────────────────────────────
output vnetId           string = vnet.id
output vnetName         string = vnet.name
output storageAccountId string = storageAccount.id
output keyVaultUri      string = keyVault.properties.vaultUri
output logWorkspaceId   string = logWorkspace.id
output resourceGroupId  string = resourceGroup().id
