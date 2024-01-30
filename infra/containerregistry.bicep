param registry_name string

param location string = resourceGroup().location

param managedIdentityNamePrefix string

param environmentsuffix string 

param projectname string

param tenantid string 

param svcprincipleforpipeline string 

param svcprincipleforplatformteam string 

param rootzonename string

var keyvaultname = 'kv-${projectname}-${environmentsuffix}-v1'

var dnszonename = '${environmentsuffix}.${rootzonename}'

var managedIdentityName = '${managedIdentityNamePrefix}-${environmentsuffix}'



var acrPullRole = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d')
var kvsecretsofficer = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7')
var dnszonecontributor = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'befefa01-2a29-4197-83a8-272ff33ce314')

resource registry_resource 'Microsoft.ContainerRegistry/registries@2023-01-01-preview' = {
  name: registry_name
  location: location
  sku: {
    name: 'Basic'
  }
  properties: {
    adminUserEnabled: true
    policies: {
      quarantinePolicy: {
        status: 'disabled'
      }
      trustPolicy: {
        type: 'Notary'
        status: 'disabled'
      }
      retentionPolicy: {
        days: 7
        status: 'disabled'
      }
      exportPolicy: {
        status: 'enabled'
      }
      azureADAuthenticationAsArmPolicy: {
        status: 'enabled'
      }
      softDeletePolicy: {
        retentionDays: 7
        status: 'disabled'
      }
    }
    encryption: {
      status: 'disabled'
    }
    dataEndpointEnabled: false
    publicNetworkAccess: 'Enabled'
    networkRuleBypassOptions: 'AzureServices'
    zoneRedundancy: 'Disabled'
    anonymousPullEnabled: false
  }
}

/*
The managed identity is created and assigned to the rbac container registry . The MI wil be 
attached to the container instance thereby helping it to pull the ACR image . 
*/
resource managedIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: managedIdentityName
  location: location
}

/*
The managed identity is assigned a roll of acrPullRole for pulling the image from the registry
*/
resource rollAssignentforContInstOnContainerRegistry 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, registry_resource.name, acrPullRole)
  scope: registry_resource
  properties: {
    description: 'Rbac roll assignment'
    principalId: managedIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: acrPullRole
  }
}


resource keyvault 'Microsoft.KeyVault/vaults@2022-07-01' = {
  name: keyvaultname
  location: location
  properties: {
    enabledForDeployment: true
    enabledForDiskEncryption: true
    enabledForTemplateDeployment: true
    enablePurgeProtection: true
    enableRbacAuthorization: true
    enableSoftDelete: true
    publicNetworkAccess: 'Enabled'
    sku: {
      family: 'A'
      name: 'standard'
    }
    softDeleteRetentionInDays: 7
    tenantId: tenantid
  }
}

resource rollAssignentforpipelineonkeyvault 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, keyvault.name, 'kvsecretsofficerforpipeline')
  scope: keyvault
  properties: {
    description: 'Rbac roll assignment'
    principalId: svcprincipleforpipeline
    principalType: 'ServicePrincipal'
    roleDefinitionId: kvsecretsofficer
  }
}

resource rollAssignentformanagedidentityonkeyvault 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, keyvault.name, 'kvsecretsofficerformi')
  scope: keyvault
  properties: {
    description: 'Rbac roll assignment'
    principalId: managedIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: kvsecretsofficer
  }
}

resource rollAssignentforplatformteamonkeyvault 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, keyvault.name, 'kvsecretsofficerforplatformteam')
  scope: keyvault
  properties: {
    description: 'Rbac roll assignment'
    principalId: svcprincipleforplatformteam
    principalType: 'Group'
    roleDefinitionId: kvsecretsofficer
  }
}


resource zone 'Microsoft.Network/dnsZones@2018-05-01' = {
  name: dnszonename
  location: 'global'
}

resource rollAssignentformiondns 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, zone.name, 'dnscontributormi')
  scope: zone
  properties: {
    description: 'Rbac roll assignment'
    principalId: managedIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: dnszonecontributor
  }
}





output managedIdentity string = managedIdentity.id
output keyvaultname string = keyvault.name
output managedIdentityname string = managedIdentity.name
output dnszonename string = zone.name
