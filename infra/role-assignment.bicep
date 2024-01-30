param resourceGroupName string

param principalId string


var Owner = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '8e3af657-a8ff-443c-a75c-2fe8c4bcb635')


resource rollAssignentforApSp 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, resourceGroupName,'Owner')
  properties: {
    description: 'Rbac roll assignment for azure pipeline'
    principalId: principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: Owner
  }
}
