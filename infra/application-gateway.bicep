@description('The location into which the Application Gateway resources should be deployed.')
param location string

@description('The domain name label to attach to the Application Gateway\'s public IP address. This must be unique within the specified location.')
param publicIPAddressDomainNameLabel string = 'appgw${uniqueString(resourceGroup().id)}'

@description('The minimum number of capacity units for the Application Gateway to use when autoscaling.')
param minimumCapacity int = 1

@description('The maximum number of capacity units for the Application Gateway to use when autoscaling.')
param maximumCapacity int = 3

@description('The IP address of the backend to configure in Application Gateway.')
param backendipaddressobject object


// @description('The resource ID of the virtual network subnet that the Application Gateway should be deployed into.')
// param subnetResourceId string

@description('The Frontend port for the application Gateway')
param applicationGatewayFrontendPort int

@description('The Backend port for the application Gateway.')
param applicationGatewayBackendPort int

@description('The domain name of the app.')
param domainname string

@description('Managed Identity ID that needs to be attached to the container group for pulling an image')
param managedIdentity string

@description('The application gateway frontend ports.')
param applicationGatewayFrontendhttpsPort int

@description('The name of the subnet where the container needs to be deployed')
param appgwsubnetname string 

@description('The name of the vnet where the container needs to be deployed')
param vnetname string 

@description('The resource group where the network infrastructure is deployed')
param resourcegroupnetwork string 

@description('The resource group where the keyvault is deployed')
param resourcegroupstateful string 

@description('The name of the keyvault where the certificate is stored')
param keyvaultname string


var publicIPAddressName = 'MyApplicationGateway-PIP'
var applicationGatewayName = 'MyApplicationGateway'
var gatewayIPConfigurationName = 'MyGatewayIPConfiguration'
var frontendIPConfigurationName = 'MyFrontendIPConfiguration'
var frontendPort = applicationGatewayFrontendPort
var frontendhttpsPort = applicationGatewayFrontendhttpsPort
var frontendPortName = 'MyFrontendPort'
var frontendPorthttpsName = 'MyFrontendPorthttps'
var backendPort = applicationGatewayBackendPort
var backendAddressPoolName = 'MyBackendAddressPool'
var backendHttpSettingName = 'MyBackendHttpSetting'
var httpListenerName = 'MyHttpListener'
var requestRoutingRuleName = 'MyRequestRoutingRule'
var httpsListenerName = 'MyHttpsListener'


var backendipaddress = backendipaddressobject.ip

resource keyvaultsymboliclink 'Microsoft.KeyVault/vaults@2022-07-01' existing = {
  name: keyvaultname
  scope: resourceGroup(resourcegroupstateful)
}

resource vnetsymboliclink 'Microsoft.Network/virtualNetworks@2020-06-01' existing = {
  name: vnetname
  scope: resourceGroup(resourcegroupnetwork)
}

resource subnetsymboliclink 'Microsoft.Network/virtualNetworks/subnets@2023-04-01' existing = {
  parent: vnetsymboliclink
  name: appgwsubnetname
}

resource publicIPAddress 'Microsoft.Network/publicIPAddresses@2020-06-01' = {
  name: publicIPAddressName
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
    dnsSettings: {
      domainNameLabel: publicIPAddressDomainNameLabel
    }
  }
}

resource applicationGateway 'Microsoft.Network/applicationGateways@2021-05-01' = {
  name: applicationGatewayName
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${managedIdentity}': {}
    }
  }
  properties: {
    sku: {
      name: 'Standard_v2'
      tier: 'Standard_v2'
    }
    autoscaleConfiguration: {
      minCapacity: minimumCapacity
      maxCapacity: maximumCapacity
    }
    gatewayIPConfigurations: [
      {
        name: gatewayIPConfigurationName
        properties: {
          subnet: {
            id: subnetsymboliclink.id
          }
        }
      }
    ]
    frontendIPConfigurations: [
      {
        name: frontendIPConfigurationName
        properties: {
          publicIPAddress: {
            id: publicIPAddress.id
          }
        }
      }
    ]
    frontendPorts: [
      {
        name: frontendPortName
        properties: {
          port: frontendPort
        }
      }
      {
        name: frontendPorthttpsName
        properties: {
          port: frontendhttpsPort
        }
      }
    ]
    backendAddressPools: [
      {
        name: backendAddressPoolName
        properties: {
          backendAddresses: [
            {
              ipAddress: backendipaddress
            }
          ]
        }
      }
    ]
    backendHttpSettingsCollection: [
      {
        name: backendHttpSettingName
        properties: {
          port: backendPort
          protocol: 'Http'
          cookieBasedAffinity: 'Disabled'
          hostName: domainname
          pickHostNameFromBackendAddress: false
          requestTimeout: 30
          probe:{
            id: resourceId('Microsoft.Network/applicationGateways/probes', applicationGatewayName, 'ouathproxyprobe')

          }
        }
      }
    ]
    sslCertificates: [
      {
        name: 'certificate'
        properties: {
          keyVaultSecretId: '${keyvaultsymboliclink.properties.vaultUri}secrets/certificate/'
        }
      }
    ]
    httpListeners: [
      {
        name: httpListenerName
        properties: {
          frontendIPConfiguration: {
            id: resourceId('Microsoft.Network/applicationGateways/frontendIPConfigurations', applicationGatewayName, frontendIPConfigurationName)
          }
          frontendPort: {
            id: resourceId('Microsoft.Network/applicationGateways/frontendPorts', applicationGatewayName, frontendPortName)
          }
          protocol: 'Http'
        }
      }
      {
        name: httpsListenerName
        properties: {
          frontendIPConfiguration: {
            id: resourceId('Microsoft.Network/applicationGateways/frontendIPConfigurations', applicationGatewayName, frontendIPConfigurationName)
          }
          frontendPort: {
            id: resourceId('Microsoft.Network/applicationGateways/frontendPorts', applicationGatewayName, frontendPorthttpsName)
          }
          protocol: 'Https'
          sslCertificate: {
            id: resourceId('Microsoft.Network/applicationGateways/sslCertificates',applicationGatewayName,'certificate')
          }
        }
      }
    ]

    probes: [
      {
        name: 'ouathproxyprobe'
        properties: {
          interval: 30
          match: {
            statusCodes: [
              '200-399'
            ]
          }
          minServers: 0
          path: '/ping'
          pickHostNameFromBackendHttpSettings: true
          protocol: 'Http'
          timeout: 30
          unhealthyThreshold: 3
        }
      }
    ]
    requestRoutingRules: [
      {
        name: requestRoutingRuleName
        properties: {
          ruleType: 'Basic'
          httpListener: {
            id: resourceId('Microsoft.Network/applicationGateways/httpListeners', applicationGatewayName, httpsListenerName)
          }
          backendAddressPool: {
            id: resourceId('Microsoft.Network/applicationGateways/backendAddressPools', applicationGatewayName, backendAddressPoolName)
          }
          backendHttpSettings: {
            id: resourceId('Microsoft.Network/applicationGateways/backendHttpSettingsCollection', applicationGatewayName, backendHttpSettingName)
          }
        }
      }
    ]
  }
}


output applicationGatewayResourceId string = applicationGateway.id
output publicIPAddressHostName string = publicIPAddress.properties.dnsSettings.fqdn
