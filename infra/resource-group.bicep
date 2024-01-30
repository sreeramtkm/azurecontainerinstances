targetScope = 'subscription'
param location string = 'norwayeast'
param resourceGroupName string 
param principalId string


resource rg 'Microsoft.Resources/resourceGroups@2021-04-01' = {
  name: resourceGroupName
  location: location

}

/*
This is the role assignment for assigning the contributor pipeline role  owner permissions 
on the resource group that is created . The role assignment has to be modularized as the role 
assignment is on a different scope(resource group)
*/


module rollassignmentModule './role-assignment.bicep' = {
  dependsOn: [
    rg
  ]
  name: 'roleassignment'
  scope: resourceGroup(resourceGroupName)
  params: {
    resourceGroupName: resourceGroupName
    principalId: principalId
  }
}
