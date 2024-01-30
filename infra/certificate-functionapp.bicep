// param subscriptionId string
param nameindicator string
param location string
param use32BitWorkerProcess bool
param ftpsState string
param linuxFxVersion string
param sku string
param skuCode string
// param tenantId string
param managedIdentityName string
param projectname string
param environment string
param resourcegroupstateful string

/*
The secret_reader and the secret_officer variables are built-in roles and will remain the same across tenants
*/
// var secret_reader = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
// var secret_officer = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7')
var storageaccountname = 'sa${projectname}${environment}'
var hostingplanname = 'hostingplan-${projectname}-${environment}'
var name = '${nameindicator}${projectname}${environment}'


resource miAppMonFn 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = {
  name: managedIdentityName
  scope: resourceGroup(resourcegroupstateful)
}


resource functionapplinux 'Microsoft.Web/sites@2022-03-01' = {
  name: name
  kind: 'functionapp,linux'
/*
The identity assigned is user assigned rather than system assigned . System assigned is probably the best to associate with a 
resource as it will be tied to the lifecycle of the resource. But since the function using Azure AD graph API permissions for the 
same need to be assigned by an global administrator or an application administrator. Hence decided to have this as a user assigned
identity
*/ 
  identity:{
    type: 'UserAssigned'
    userAssignedIdentities:{
      '${miAppMonFn.id}': {}
    }
  }
  location: location
  tags: {}
  properties: {
    enabled:true
    siteConfig: {

/* Below configs are required for the deployment and the functioning of the function app.  The appinsights key is required
   for the application to do trace logging
*/
      appSettings: [
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~4'
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: 'python'
        }
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageaccountname};AccountKey=${listKeys(storageAccount.id, '2019-06-01').keys[0].value};EndpointSuffix=core.windows.net'
        }
        {
          name: 'WEBSITE_CONTENTAZUREFILECONNECTIONSTRING'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageaccountname};AccountKey=${listKeys(storageAccount.id, '2019-06-01').keys[0].value};EndpointSuffix=core.windows.net'
        }
        {
          name: 'WEBSITE_CONTENTSHARE'
          value: '${projectname}-${environment}'
        }
        {
          name: 'APPINSIGHTS_INSTRUMENTATIONKEY'
          value: applicationInsights.properties.InstrumentationKey
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: applicationInsights.properties.ConnectionString
        }
        {
          name: 'AZURE_CLIENT_ID'
          value: miAppMonFn.properties.clientId
        }
        {
          name: 'environment'
          value: environment
        }
      ]
      cors: {
        allowedOrigins: [
          'https://portal.azure.com'
        ]
      }
      use32BitWorkerProcess: use32BitWorkerProcess
      ftpsState: ftpsState
      linuxFxVersion: linuxFxVersion
    }
    serverFarmId: hostingPlan.id
    clientAffinityEnabled: false
/*
    The virtual network is not enabled as this function do not need to connect to any resources in the virtual network
*/
    virtualNetworkSubnetId: null
    httpsOnly: true
    publicNetworkAccess: 'Enabled'
  }
}

/*The managed identity is used here by the python code running in the function app to generate short lived credentials necessary to authenticate
against graph api's
*/




resource hostingPlan 'Microsoft.Web/serverfarms@2022-03-01' = {
  name: hostingplanname
  location: location
  kind: 'linux'
  tags: {}
  properties: {
    reserved: true
  }
  sku: {
    tier: sku
    name: skuCode
  }
  dependsOn: []
}

/*
The storage account is used for storing the code which is run on the function app. It is also used for persisting the 
function app settings , secrets , and logs . 
*/
resource storageAccount 'Microsoft.Storage/storageAccounts@2022-09-01' = {
  name: storageaccountname
  kind: 'Storage'
  location: location
  tags: {}
  sku: {
    name: 'Standard_LRS'
  }
  properties: {
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    defaultToOAuthAuthentication: true
    allowBlobPublicAccess: false
  }
}

/*
Application insights resource is used for azure monitor 
*/

resource applicationInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: name
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    Request_Source: 'rest'
    IngestionMode: 'LogAnalytics'
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
    WorkspaceResourceId: '/subscriptions/62a2dbbc-8e28-47d5-9865-5cb8c66f0d8e/resourcegroups/rg-central-logging/providers/microsoft.operationalinsights/workspaces/ngi-central-log-analytics'
  }
}
