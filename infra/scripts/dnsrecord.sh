#!/bin/bash

while getopts ":a:b:c:d:e:" opt; do
  case $opt in
     a)
       appgwdeploymentname="$OPTARG";;
       
    
     b)
       acrdeploymentname="$OPTARG";;
     
     c)
       rgstatefulsvc="$OPTARG";; 

     d)
       rgstatelesssvc="$OPTARG";;

     e)
       environment="$OPTARG";;       
  esac
done

echo "The values of the variables passed on to the script below"
echo $appgwdeploymentname
echo $acrdeploymentname
echo $rgstatefulsvc
echo $rgstatelesssvc
echo $environment


#Install yq and give executable perms
wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O ./yq && chmod +x ./yq


# Getting the DNS zone name 
echo "Getting the dns zone name"
echo $acrdeploymentname
echo $rgstatefulsvc
dnszonename=$(az stack group show --name $acrdeploymentname --resource-group $rgstatefulsvc --query outputs.dnszonename.value)
./yq -i ".parameters.dnszonename.value=$dnszonename" $environment.parameters.dnsrecord.json 

#Getting the dns record from the app gw deployment stack
echo "Getting the dns record name"
apidnsrecord=$(az stack group show --name $appgwdeploymentname --resource-group $rgstatelesssvc --query outputs.publicIPAddressHostName.value)
./yq -i ".parameters.apidnsrecord.value=$apidnsrecord" $environment.parameters.dnsrecord.json 

