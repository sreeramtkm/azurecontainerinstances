#!/bin/bash

while getopts ":a:b:c:d:e:f:g:h:" opt; do
  case $opt in
     a)
       registry="$OPTARG";;
       
    
     b)
       acrdeploymentname="$OPTARG";;
     
     c)
       rgstatefulsvc="$OPTARG";;

     d)
       networkstackname="$OPTARG";;

     e)
       rgnetwork="$OPTARG";;

     f)
       containergrpdeploymentname="$OPTARG";;

     g)
       rgstatelesssvc="$OPTARG";;

     h)
       environment="$OPTARG";;        
  esac
done

echo $registry
echo $acrdeploymentname
echo $rgstatefulsvc
echo $networkstackname
echo $rgnetwork
echo $containergrpdeploymentname
echo $rgstatelesssvc
echo $environment

wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O ./yq && chmod +x ./yq


#Getting the managed identity
identity=$(az stack group show -g $rgstatefulsvc -n $acrdeploymentname --query outputs.managedIdentity.value)
echo $identity
./yq -i ".parameters.managedIdentity.value=$identity" $environment.parameters.app-gw.json

#Getting the resource group stateful
resourcegroupstatefulsvc="\"$rgstatefulsvc\""
echo $resourcegroupstatefulsvc
./yq -i ".parameters.resourcegroupstateful.value=$resourcegroupstatefulsvc" $environment.parameters.app-gw.json

# Getting the subnet name for the container group subnet
subnetname=$(az stack group show --name $networkstackname --resource-group $rgnetwork --query outputs.appgwsubnetname.value)
./yq -i ".parameters.appgwsubnetname.value=$subnetname" $environment.parameters.app-gw.json 

# Getting the vnet name for the container group subnet
vnetname=$(az stack group show --name $networkstackname --resource-group $rgnetwork --query outputs.vnetname.value)
./yq -i ".parameters.vnetname.value=$vnetname" $environment.parameters.app-gw.json 

# Writing the resource group of the network infrastructure to the container parameter file
resourcegroupnetwork="\"$rgnetwork\""
echo $resourcegroupnetwork
./yq -i ".parameters.resourcegroupnetwork.value=$resourcegroupnetwork" $environment.parameters.app-gw.json 


#Getting the backend ip address for the oauth . If we are implementing oauthproxy then this would be the IP address of oauth
#proxy container
backendipaddressobject=$(az stack group show --name $containergrpdeploymentname --resource-group $rgstatelesssvc --query outputs.containerIPv4AddressForoauthproxy.value)
./yq -i ".parameters.backendipaddressobject.value=$backendipaddressobject" $environment.parameters.app-gw.json

#Getting the keyvault name
keyvaultname=$(az stack group show -g $rgstatefulsvc -n $acrdeploymentname --query outputs.keyvaultname.value)
./yq -i ".parameters.keyvaultname.value=$keyvaultname" $environment.parameters.app-gw.json 
