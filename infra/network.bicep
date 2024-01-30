@description('The location into which the virtual network resources should be deployed.')
param location string

@description('The IP address prefix (CIDR range) to use when deploying the virtual network.')
param vnetIPPrefix string

@description('The IP address prefix (CIDR range) to use when deploying the container group subnet within the virtual network.')
param containerInstancesSubnetIPPrefix string

@description('The IP address prefix (CIDR range) to use when deploying the Application Gateway subnet within the virtual network.')
param applicationGatewaySubnetIPPrefix string

var vnetName = 'VNet'
var containerGroupSubnetName = 'Containers'
var applicationGatewaySubnetName = 'ApplicationGateway'
var nsgName = 'MyNSG'

resource vnet 'Microsoft.Network/virtualNetworks@2020-06-01' = {
  name: vnetName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        vnetIPPrefix
      ]
    }
    subnets: [
      {
        name: containerGroupSubnetName
        properties: {
          addressPrefix: containerInstancesSubnetIPPrefix
          delegations: [
            {
              name: 'DelegationService'
              properties: {
                serviceName: 'Microsoft.ContainerInstance/containerGroups'
              }
            }
          ]
        }
      }
      {
        name: applicationGatewaySubnetName
        properties: {
          addressPrefix: applicationGatewaySubnetIPPrefix
          networkSecurityGroup: {
            id: nsg.id
          }
        }
      }
    ]
  }
}

resource nsg 'Microsoft.Network/networkSecurityGroups@2020-05-01' = {
  name: nsgName
  location: location
  properties: {
    securityRules: [
      {
        name: 'Allow_GWM'
        properties: {
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '65200-65535'
          sourceAddressPrefix: 'GatewayManager'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 100
          direction: 'Inbound'
        }
      }
      {
        name: 'Allow_AzureLoadBalancer'
        properties: {
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: 'AzureLoadBalancer'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 110
          direction: 'Inbound'
        }
      }
      {
        name: 'Allow_Internet traffic'
        properties: {
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: '0.0.0.0/0'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 140
          direction: 'Inbound'
        }
      }
    ]
  }
}

output vnetname string = vnetName
output subnetname string = containerGroupSubnetName
output appgwsubnetname string = applicationGatewaySubnetName
output vnetResourceId string = vnet.id
output applicationGatewaySubnetResourceId string = resourceId('Microsoft.Network/virtualNetworks/subnets', vnetName, applicationGatewaySubnetName)
output containerGroupSubnetResourceId string = resourceId('Microsoft.Network/virtualNetworks/subnets', vnetName, containerGroupSubnetName)
