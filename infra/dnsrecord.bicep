@description('The dns zone name')
param dnszonename string

@description('The dns zone record for the api')
param apidnsrecord string



resource dnssymboliclink 'Microsoft.Network/dnsZones@2018-05-01' existing = {
  name: dnszonename
}


resource record 'Microsoft.Network/dnsZones/CNAME@2018-05-01' = {
  parent: dnssymboliclink
  name: 'app'
  properties: {
    TTL: 300
    CNAMERecord: {
      cname: apidnsrecord
    }
  }
}
