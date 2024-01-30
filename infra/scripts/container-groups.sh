#!/bin/bash
while getopts ":a:b:c:d:e:f:g:" opt; do
  case $opt in
     a)
       registry="$OPTARG";;
       
     b)
       reponame="$OPTARG";;
    
     c)
       acrdeploymentname="$OPTARG";;
     
     d)
       rgstatefulsvc="$OPTARG";;

     e)
       networkstackname="$OPTARG";;

     f)
       rgnetwork="$OPTARG";;

     g)
       environment="$OPTARG";;      
  esac
done

echo "registry: $registry";
echo "reponame: $reponame";
echo "environment: $environment";


#Install yq and give executable perms
wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O ./yq && chmod +x ./yq

./yq -i ".parameters.registry.value=\"$registry\"" $environment.parameters.container-groups.json



img_name="$registry.azurecr.io/$reponame"
echo $img_name
./yq -i ".parameters.image.value=\"$img_name\"" $environment.parameters.container-groups.json

#Get the latest tag 
latesttag=$(az acr repository show-tags -n $registry --repository $reponame | jq '.[-1]')
latesttag=$(echo $latesttag | tr -d '"')
echo $latesttag
./yq -i ".parameters.tag.value=$latesttag" $environment.parameters.container-groups.json

# Get the managed identity
identity=$(az stack group show -g $rgstatefulsvc -n $acrdeploymentname --query outputs.managedIdentity.value)
echo $identity
./yq -i ".parameters.managedIdentity.value=$identity" $environment.parameters.container-groups.json 

# Get the ouathimage version
oauthimgversion=$(az acr repository show-tags -n $registry --repository oauth2-proxy | jq '.[-1]')
echo $oauthimgversion
./yq -i ".parameters.oauthimgversion.value=$oauthimgversion" $environment.parameters.container-groups.json 

#Getting the keyvault name
kv=$(az stack group show -g $rgstatefulsvc -n $acrdeploymentname --query outputs.keyvaultname.value)
kv=$(echo $kv | tr -d '"')
echo $kv

# Get the oauthproxy cookie secret
kvquery=$(az keyvault secret show --vault-name $kv --name oauth2proxycookiesecret)
oauth2proxycookiesecret=`echo $kvquery | jq '.value'`
echo $oauth2proxycookiesecret
./yq -i ".parameters.oauth2proxycookiesecret.value=$oauth2proxycookiesecret" $environment.parameters.container-groups.json


# Get the oauth2proxy client and the cookie secret 
kvquery=$(az keyvault secret show --vault-name $kv --name oauth2proxyclientsecret)
echo $kvquery
oauth2proxyclientsecret=`echo $kvquery | jq '.value'`
echo $oauth2proxyclientsecret
./yq -i ".parameters.oauth2proxyclientsecret.value=$oauth2proxyclientsecret" $environment.parameters.container-groups.json

#Getting the oauthproxy image and the version
oauthproxyimgname="$registry.azurecr.io/oauth2-proxy"
./yq -i ".parameters.oauthproxyimage.value=\"$oauthproxyimgname\"" $environment.parameters.container-groups.json


# Getting the subnet name for the container group subnet
subnetname=$(az stack group show --name $networkstackname --resource-group $rgnetwork --query outputs.subnetname.value)
./yq -i ".parameters.containersubnetname.value=$subnetname" $environment.parameters.container-groups.json

# Getting the vnet name for the container group subnet
vnetname=$(az stack group show --name $networkstackname --resource-group $rgnetwork --query outputs.vnetname.value)
./yq -i ".parameters.vnetname.value=$vnetname" $environment.parameters.container-groups.json

# Writing the resource group of the network infrastructure to the container parameter file
resourcegroupnetwork="\"$rgnetwork\""
echo $resourcegroupnetwork
./yq -i ".parameters.resourcegroupnetwork.value=$resourcegroupnetwork" $environment.parameters.container-groups.json
