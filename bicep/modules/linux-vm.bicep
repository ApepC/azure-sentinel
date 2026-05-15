// ── Linux VM Module ──────────────────────────────────────────
// Deploys a hardened Ubuntu 22.04 LTS VM with:
// - MMA/OMS agent for Log Analytics
// - No public IP (management via Bastion)
// - Premium SSD OS disk with encryption
// ─────────────────────────────────────────────────────────────

param prefix string
param location string
param tags object
param subnetId string
param adminUsername string
@secure()
param adminPassword string
param logWorkspaceId string
@secure()
param logWorkspaceKey string

@allowed(['Standard_B2s', 'Standard_B4ms', 'Standard_D2s_v5'])
param vmSize string = 'Standard_B2s'

var vmName = 'vm-${prefix}'
var osDiskName = 'osdisk-${vmName}'
var nicName = 'nic-${vmName}'

// ── NIC — private IP only, no public IP ─────────────────────
resource nic 'Microsoft.Network/networkInterfaces@2023-04-01' = {
  name: nicName
  location: location
  tags: tags
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: { id: subnetId }
          privateIPAllocationMethod: 'Dynamic'
        }
      }
    ]
  }
}

// ── Virtual Machine ──────────────────────────────────────────
resource vm 'Microsoft.Compute/virtualMachines@2023-07-01' = {
  name: vmName
  location: location
  tags: tags
  identity: { type: 'SystemAssigned' }   // Managed identity for Key Vault access
  properties: {
    hardwareProfile: { vmSize: vmSize }
    osProfile: {
      computerName: vmName
      adminUsername: adminUsername
      adminPassword: adminPassword
      linuxConfiguration: {
        disablePasswordAuthentication: false
        patchSettings: {
          patchMode: 'AutomaticByPlatform'
          assessmentMode: 'AutomaticByPlatform'
        }
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'Canonical'
        offer: '0001-com-ubuntu-server-jammy'
        sku: '22_04-lts-gen2'
        version: 'latest'
      }
      osDisk: {
        name: osDiskName
        createOption: 'FromImage'
        managedDisk: { storageAccountType: 'Premium_LRS' }
        deleteOption: 'Delete'
        diskSizeGB: 64
      }
    }
    networkProfile: {
      networkInterfaces: [{ id: nic.id, properties: { deleteOption: 'Delete' } }]
    }
    securityProfile: {
      uefiSettings: {
        secureBootEnabled: true
        vTpmEnabled: true
      }
      securityType: 'TrustedLaunch'
    }
    diagnosticsProfile: {
      bootDiagnostics: { enabled: true }
    }
  }
}

// ── OMS Extension → Log Analytics ───────────────────────────
resource omsExtension 'Microsoft.Compute/virtualMachines/extensions@2023-07-01' = {
  parent: vm
  name: 'OmsAgentForLinux'
  location: location
  properties: {
    publisher: 'Microsoft.EnterpriseCloud.Monitoring'
    type: 'OmsAgentForLinux'
    typeHandlerVersion: '1.19'
    autoUpgradeMinorVersion: true
    settings: {
      workspaceId: logWorkspaceId
    }
    protectedSettings: {
      workspaceKey: logWorkspaceKey
    }
  }
}

// ── Auto-Shutdown (cost control) ─────────────────────────────
resource autoShutdown 'Microsoft.DevTestLab/schedules@2018-09-15' = {
  name: 'shutdown-computevm-${vmName}'
  location: location
  properties: {
    status: 'Enabled'
    taskType: 'ComputeVmShutdownTask'
    dailyRecurrence: { time: '2300' }
    timeZoneId: 'UTC'
    targetResourceId: vm.id
  }
}

output vmId   string = vm.id
output vmName string = vm.name
output principalId string = vm.identity.principalId
