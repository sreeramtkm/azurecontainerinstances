
@description('Name for the app container group')
param appname string = 'soiltcontainergroup'

@description('Name for the oauthproxy container group')
param oauthname string = 'oauthcontainergroup'

@description('Location for all resources.')
param location string = resourceGroup().location

@description('Container image to deploy. Should be of the form repoName/imagename:tag for images stored in public Docker Hub, or a fully qualified URI for other registries. Images from private registries require additional registry credentials.')
param image string 

@description('Port to open on the container and the public IP address.')
param port int 

@description('The number of CPU cores to allocate to the app container.')
param cpucoresforapp int = 1

@description('The amount of memory to allocate to the container in gigabytes for app container.')
param memoryingbforapp int = 1

@description('The number of CPU cores to allocate to the app container.')
param cpucoresforoauthproxy int = 1

@description('The amount of memory to allocate to the container in gigabytes for app container.')
param memoryingbforoauthproxy int = 1

@description('The behavior of Azure runtime if container has stopped.')
@allowed([
  'Always'
  'Never'
  'OnFailure'
])
param restartPolicy string = 'OnFailure'

@description('The tag of the image to deploy to container instance.')
param tag int 

@description('Managed Identity ID that needs to be attached to the container group for pulling an image')
param managedIdentity string

@description('Registry Name')
param registry string


@description('OauthProxy image version')
param oauthimgversion string

@description('OauthProxy image version')
param oauthproxyimage string

@secure()
@description('The oauth2 client secret')
param oauth2proxyclientsecret string 

@secure()
@description('The oauth2 proxy cookie secret')
param oauth2proxycookiesecret string 

@description('The name of the subnet where the container needs to be deployed')
param containersubnetname string 

@description('The name of the vnet where the container needs to be deployed')
param vnetname string 

@description('The resource group where the network infrastructure is deployed')
param resourcegroupnetwork string 

@description('The resource group where the network infrastructure is deployed')
param oauthproxyoidcissuerurl string 

@description('The doman name for the app')
param domainname string

@description('The doman name for the app')
param oauthproxyclientid string



resource vnetsymboliclink 'Microsoft.Network/virtualNetworks@2020-06-01' existing = {
  name: vnetname
  scope: resourceGroup(resourcegroupnetwork)
}

resource subnetsymboliclink 'Microsoft.Network/virtualNetworks/subnets@2023-04-01' existing = {
  parent: vnetsymboliclink
  name: containersubnetname
}



resource containerGroupForOauthProxy 'Microsoft.ContainerInstance/containerGroups@2021-09-01' = {
  name: appname
  location: location
  identity:{
    type: 'UserAssigned'
    userAssignedIdentities:{
      '${managedIdentity}': {}
    }
  }
  properties: {
    containers: [
      {
        name: oauthname
        properties: {
          image: '${oauthproxyimage}:${oauthimgversion}'
          environmentVariables:[
            {
              name: 'OAUTH2_PROXY_PROVIDER'
              value: 'azure'
            }
            {
              name: 'OAUTH2_PROXY_AZURE_TENANT'
              value: '51b6ad1f-28c7-4c49-b6b3-0708b2a3f62e'
            }
            {
              name: 'OAUTH2_PROXY_CLIENT_ID'
              value: oauthproxyclientid
            }
            {
              name: 'OAUTH2_PROXY_CLIENT_SECRET'
              secureValue: oauth2proxyclientsecret
            }
            {
              name: 'OAUTH2_PROXY_REDIRECT_URL'
              value: 'https://${domainname}/oauth2/callback'
            }
            {
              name: 'OAUTH2_PROXY_OIDC_ISSUER_URL'
              value: oauthproxyoidcissuerurl
            }
            {
              name: 'OAUTH2_PROXY_COOKIE_SECRET'
              secureValue: oauth2proxycookiesecret
            }
            {
              name: 'OAUTH2_PROXY_EMAIL_DOMAINS'
              value: 'ngi.no'
            }
            {
              name: 'OAUTH2_PROXY_COOKIE_SECURE'
              value: 'true'
            }
            {
              name: 'OAUTH2_PROXY_COOKIE_DOMAIN'
              value: '*'
            }
            {
              name: 'OAUTH2_PROXY_UPSTREAMS'
              value: 'http://127.0.0.1:80'
            }
            {
              name: 'OAUTH2_PROXY_HTTP_ADDRESS'
              value: '0.0.0.0:4180'
            }
            {
              name: 'OAUTH2_PROXY_PASS_AUTHORIZATION_HEADER'
              value: 'true'
            }
            {
              name: 'OAUTH2_PROXY_REVERSE_PROXY'
              value: 'true'
            }  
          ]
          ports: [
            {
              port: 4180
              protocol: 'TCP'
            }
          ]
          resources: {
            requests: {
              cpu: cpucoresforoauthproxy
              memoryInGB: memoryingbforoauthproxy
            }
          }
        }
      }
      {
        name: appname
        properties: {
          image: '${image}:${tag}'
          ports: [
            {
              port: port
              protocol: 'TCP'
            }
          ]
          resources: {
            requests: {
              cpu: cpucoresforapp
              memoryInGB: memoryingbforapp
            }
          }
        }
      }
    ]
    osType: 'Linux'
    restartPolicy: restartPolicy
    imageRegistryCredentials: [
      {
        server: '${registry}.azurecr.io'
        identity: managedIdentity
      }
    ]
    ipAddress: {
      type: 'Private'
      ports: [
        {
          port: 4180
          protocol: 'TCP'
        }
      ]
    }
    subnetIds:[
      {
        id: subnetsymboliclink.id
      }
    ]
  }
}


output containerIPv4AddressForoauthproxy object = containerGroupForOauthProxy.properties.ipAddress
