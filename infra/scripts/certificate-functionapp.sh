#!/bin/bash
while getopts ":a:b:c:d:" opt; do
  case $opt in
     a)
       environment="$OPTARG";;
       
    
     b)
       projectname="$OPTARG";;
     
     c)
       rgstatefulsvc="$OPTARG";;

     d)
       acrdeploymentname="$OPTARG";;
       
  esac
done

echo $environment
echo $projectname
echo $rgstatefulsvc
echo $acrdeploymentname


#Install yq and give executable perms
wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O ./yq && chmod +x ./yq



#Getting the environment value
env="\"$environment\""
echo $env
./yq -i ".parameters.environment.value=$env" $environment.parameters.certificate-functionapp.json

#Getting the projectname
projectname="\"$projectname\""
echo $projectname
./yq -i ".parameters.projectname.value=$projectname" $environment.parameters.certificate-functionapp.json

#Getting the managed identity
identity=$(az stack group show --name $acrdeploymentname --resource-group $rgstatefulsvc  --query outputs.managedIdentityname.value)
echo $identity
./yq -i ".parameters.managedIdentityName.value=$identity" $environment.parameters.certificate-functionapp.json

#Getting the stateful resource group name
resourcegroupstatefulsvc="\"$rgstatefulsvc\""
echo $resourcegroupstatefulsvc
./yq -i ".parameters.resourcegroupstateful.value=$resourcegroupstatefulsvc" $environment.parameters.certificate-functionapp.json


