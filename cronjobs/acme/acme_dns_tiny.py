# !/usr/bin/env python3
# pylint: disable=multiple-imports
"""ACME client to met DNS challenge and receive TLS certificate"""
import argparse, base64, binascii, configparser, copy, hashlib, ipaddress, json, logging
import re, sys, subprocess, time
import os
import requests
import OpenSSL
import dns.exception, dns.query, dns.name, dns.resolver, dns.rrset, dns.tsigkeyring, dns.update
from azure.identity import DefaultAzureCredential
from azure.mgmt.dns import DnsManagementClient
from azure.core.exceptions import ResourceNotFoundError
from azure.keyvault.keys import KeyClient
from azure.keyvault.secrets import SecretClient
from Crypto.PublicKey import RSA
from opencensus.ext.azure.log_exporter import AzureLogHandler
import azure.functions as func
from . import crypto_util


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(AzureLogHandler())



# Certificate private key size
CERT_PKEY_BITS = 2048


def _base64(text):
    """Encodes string as base64 as specified in the ACME RFC."""
    return base64.urlsafe_b64encode(text).decode("utf8").rstrip("=")


def _openssl(command, options, communicate=None):
    """Run openssl command line and raise IOError on non-zero return."""
    openssl = subprocess.Popen(["openssl", command] + options,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    out, err = openssl.communicate(communicate)
    if openssl.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err))
    return out


# pylint: disable=too-many-locals,too-many-branches,too-many-statements
def get_crt(config, log=logger) -> str:
    """Get ACME certificate by resolving DNS challenge."""

    def _update_dns(dnsname,digest):
        #Updates DNS resource by adding or deleting resource."""
        azuresubscriptionid = config['azuresubscriptionid']
        client = DnsManagementClient(credential=DefaultAzureCredential(), subscription_id=azuresubscriptionid)
        resource_group_name = config['resourcegroupname']
        ttl = config['ttl']
        zone_name=config['dnszone']
        record_type = "TXT"
        dnsname = dnsname.to_text()
        relativednsname = dnsname.removesuffix(zone_name).rstrip('.')
        logger.info(relativednsname)
        response = client.record_sets.create_or_update(resource_group_name,zone_name,relativednsname,record_type,
                                            {
                                                'ttl': ttl,
                                                'txt_records': [
                                                    {
                                                        'value': [
                                                            digest
                                                        ]
                                                    }
                                                    
                                                ]
                                            }
                                            )
        logger.info(response)

        if response.provisioning_state == 'Succeeded':
            return 'succeeded'
        else:
            return 'none'

    def _send_signed_request(url, payload, extra_headers=None) -> None:
        """Sends signed requests to ACME server."""
        nonlocal nonce
        if payload == "":  # on POST-as-GET, final payload has to be just empty string
            payload64 = ""
        else:
            payload64 = _base64(json.dumps(payload).encode("utf8"))
        protected = copy.deepcopy(private_acme_signature)
        protected["nonce"] = nonce or requests.get(acme_config["newNonce"]).headers['Replay-Nonce']
        del nonce
        protected["url"] = url
        if url == acme_config["newAccount"]:
            if "kid" in protected:
                del protected["kid"]
        else:
            del protected["jwk"]
        protected64 = _base64(json.dumps(protected).encode("utf8"))
        signature = _openssl("dgst", ["-sha256", "-sign", config['accountkeyfile']],
                             "{0}.{1}".format(protected64, payload64).encode("utf8"))
        print(signature)
        logger.info(signature)
        jose = {
            "protected": protected64, "payload": payload64, "signature": _base64(signature)
        }
        logger.info(jose)
        joseheaders = {'Content-Type': 'application/jose+json'}
        joseheaders.update(adtheaders)
        joseheaders.update(extra_headers or {})
        logger.info(joseheaders)
        print(joseheaders)
        try:
            response = requests.post(url, json=jose, headers=joseheaders)
            logger.info(response)
        except requests.exceptions.RequestException as error:
            response = error.response
            logger.info(response)
        if response:
            nonce = response.headers['Replay-Nonce']
            try:
                return response, response.json()
            except ValueError:  # if body is empty or not JSON formatted
                return response, json.loads("{}")
        else:
            raise RuntimeError("Unable to get response from ACME server.")

    # main code

    adtheaders = {'User-Agent': 'acme-dns-tiny/2.4',
                  'Accept-Language': 'en'}
    nonce = None

    log.info("Find domains to validate from the Certificate Signing Request (CSR) file.")
    csr = _openssl("req", ["-in", config["csrfile"],
                           "-noout", "-text"]).decode("utf8")
    domains = set()
    common_name = re.search(r"Subject:.*?\s+?CN\s*?=\s*?([^\s,;/]+)", csr)
    if common_name is not None:
        domains.add(common_name.group(1))
    subject_alt_names = re.search(
        r"X509v3 Subject Alternative Name: (?:critical)?\s+([^\r\n]+)\r?\n",
        csr, re.MULTILINE)
    if subject_alt_names is not None:
        for san in subject_alt_names.group(1).split(", "):
            if san.startswith("DNS:"):
                domains.add(san[4:])
    if len(domains) == 0:  # pylint: disable=len-as-condition
        raise ValueError("Didn't find any domain to validate in the provided CSR.")
    resolver = dns.resolver.Resolver(configure=False)
    resolver.retry_servfail = True
    nameserver = []
    try:
        ipaddress.ip_address(config['dnsservername'])
        nameserver.append(config['dnsservername'])
    except ValueError:
        log.debug("  - Configured DNS Host value is not a valid IP address, "
                  "try to resolve IP address by requesting system DNS servers.")
        try:
            nameserver += [ipv6_rrset.to_text() for ipv6_rrset
                           in dns.resolver.resolve(config['dnsservername'], rdtype="AAAA")]
        except dns.exception.DNSException:
            log.debug(("  - IPv6 addresses not found for the configured DNS Host."))
        log.info(resolver.resolve(config['dnsservername'], "A"))
        try:
            nameserver += [ipv4_rrset.to_text() for ipv4_rrset
                           in dns.resolver.resolve(config['dnsservername'], rdtype="A")]
            log.info(nameserver)
        except dns.exception.DNSException:
            log.debug("  - IPv4 addresses not found for the configured DNS Host.")
    if not nameserver:
        raise ValueError("Unable to resolve any IP address for the configured DNS Host name")
    log.info(f'The name servers are {nameserver}')
    resolver.nameservers = nameserver

    log.info("Get private signature from account key.")
    accountkey = _openssl("rsa", ["-in", config['accountkeyfile'],
                                  "-noout", "-text"])
    signature_search = re.search(r"modulus:\s+?00:([a-f0-9\:\s]+?)\r?\npublicExponent: ([0-9]+)",
                                 accountkey.decode("utf8"), re.MULTILINE)
    if signature_search is None:
        raise ValueError("Unable to retrieve private signature.")
    pub_hex, pub_exp = signature_search.groups()
    pub_exp = "{0:x}".format(int(pub_exp))
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    # That signature is used to authenticate with the ACME server, it needs to be safely kept
    private_acme_signature = {
        "alg": "RS256",
        "jwk": {
            "e": _base64(binascii.unhexlify(pub_exp.encode("utf-8"))),
            "kty": "RSA",
            "n": _base64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
        },
    }
    logger.info(private_acme_signature)
    private_jwk = json.dumps(private_acme_signature["jwk"], sort_keys=True, separators=(",", ":"))
    jwk_thumbprint = _base64(hashlib.sha256(private_jwk.encode("utf8")).digest())

    log.info("Fetch ACME server configuration from the its directory URL.")
    acme_config = requests.get(config['acmedirectory'], headers=adtheaders).json()
    terms_service = acme_config.get("meta", {}).get("termsOfService", "")

    log.info("Register ACME Account to get the account identifier.")
    account_request = {}
    if terms_service:
        account_request["termsOfServiceAgreed"] = True
        log.warning(("Terms of service exist and will be automatically agreed if possible, "
                     "you should read them: %s"), terms_service)
    http_response, account_info = _send_signed_request(acme_config["newAccount"], account_request)
    logger.info(http_response.status_code)
    if http_response.status_code == 201:
        private_acme_signature["kid"] = http_response.headers['Location']
        log.info("  - Registered a new account: '%s'", private_acme_signature["kid"])
    elif http_response.status_code == 200:
        private_acme_signature["kid"] = http_response.headers['Location']
        log.debug("  - Account is already registered: '%s'", private_acme_signature["kid"])

        http_response, account_info = _send_signed_request(private_acme_signature["kid"], "")
    else:
        raise ValueError("Error registering account: {0} {1}"
                         .format(http_response.status_code, account_info))

    log.info("Update contact information if needed.")
    if ("contact" in account_request
            and set(account_request["contact"]) != set(account_info["contact"])):
        http_response, result = _send_signed_request(private_acme_signature["kid"],
                                                     account_request)
        if http_response.status_code == 200:
            log.debug("  - Account updated with latest contact informations.")
        else:
            raise ValueError("Error registering updates for the account: {0} {1}"
                             .format(http_response.status_code, result))

    # new order
    log.info("Request to the ACME server an order to validate domains.")
    new_order = {"identifiers": [{"type": "dns", "value": domain} for domain in domains]}
    logger.info(new_order)
    http_response, order = _send_signed_request(acme_config["newOrder"], new_order)
    if http_response.status_code == 201:
        order_location = http_response.headers['Location']
        log.debug("  - Order received: %s", order_location)
        if order["status"] != "pending" and order["status"] != "ready":
            raise ValueError("Order status is neither pending neither ready, we can't use it: {0}"
                             .format(order))
    elif (http_response.status_code == 403
          and order["type"] == "urn:ietf:params:acme:error:userActionRequired"):
        raise ValueError(("Order creation failed ({0}). Read Terms of Service ({1}), then follow "
                          "your CA instructions: {2}")
                         .format(order["detail"],
                                 http_response.headers['Link'], order["instance"]))
    else:
        raise ValueError("Error getting new Order: {0} {1}"
                         .format(http_response.status_code, order))

    # complete each authorization challenge
    for authz in order["authorizations"]:
        if order["status"] == "ready":
            log.info("No challenge to process: order is already ready.")
            break

        log.info("Process challenge for authorization: %s", authz)
        # get new challenge
        http_response, authorization = _send_signed_request(authz, "")
        if http_response.status_code != 200:
            raise ValueError("Error fetching challenges: {0} {1}"
                             .format(http_response.status_code, authorization))
        domain = authorization["identifier"]["value"]

        if authorization["status"] == "valid":
            log.info("Skip authorization for domain %s: this is already validated", domain)
            continue
        if authorization["status"] != "pending":
            raise ValueError("Authorization for the domain {0} can't be validated: "
                             "the authorization is {1}.".format(domain, authorization["status"]))

        challenges = [c for c in authorization["challenges"] if c["type"] == "dns-01"]
        if not challenges:
            raise ValueError("Unable to find a DNS challenge to resolve for domain {0}"
                             .format(domain))
        log.info("Install DNS TXT resource for domain: %s", domain)
        for chal in challenges:
            log.info(chal)
        challenge = challenges[0]
        keyauthorization = challenge["token"] + "." + jwk_thumbprint
        keydigest64 = _base64(hashlib.sha256(keyauthorization.encode("utf8")).digest())
        dnsrr_domain = "_acme-challenge.{0}".format(domain)
        dnsrr_set = dns.rrset.from_text(dnsrr_domain, config['ttl'],
                                        "IN", "TXT", '"{0}"'.format(keydigest64))
        try:
             _update_dns(dnsrr_set.name,keydigest64)
        except:
            raise ValueError("Error updating the DNS")
        log.info("Wait for 1 TTL (%s seconds) to ensure DNS cache is cleared.",
                  config["ttl"])
        time.sleep(config["ttl"])
        challenge_verified = False
        number_check_fail = 1
        while challenge_verified is False:
            try:
                log.debug(('Self test (try: %s): Check resource with value "%s" exits on '
                            'nameservers: %s'), number_check_fail, keydigest64,
                            resolver.nameservers)
                for response in resolver.query(dnsrr_domain, rdtype="TXT").rrset:
                    log.debug("  - Found value %s", response.to_text())
                    challenge_verified = (challenge_verified
                                            or response.to_text() == '"{0}"'.format(keydigest64))
            except dns.exception.DNSException as dnsexception:
                log.debug(
                    "  - Will retry as a DNS error occurred while checking challenge: %s : %s",
                    type(dnsexception).__name__, dnsexception)
            finally:
                if challenge_verified is False:
                    if number_check_fail >= 10:
                        raise ValueError("Error checking challenge, value not found: {0}"
                                            .format(keydigest64))
                    number_check_fail = number_check_fail + 1
                    time.sleep(config["ttl"])


        log.info("Asking ACME server to validate challenge.")
        http_response, result = _send_signed_request(challenge["url"], {})
        if http_response.status_code != 200:
            raise ValueError("Error triggering challenge: {0} {1}"
                             .format(http_response.status_code, result))
        try:
            while True:
                http_response, challenge_status = _send_signed_request(challenge["url"], "")
                if http_response.status_code != 200:
                    raise ValueError("Error during challenge validation: {0} {1}".format(
                        http_response.status_code, challenge_status))
                if challenge_status["status"] == "pending":
                    time.sleep(2)
                elif challenge_status["status"] == "valid":
                    log.info("ACME has verified challenge for domain: %s", domain)
                    break
                else:
                    raise ValueError("Challenge for domain {0} did not pass: {1}".format(
                        domain, challenge_status))
        finally:
            print("Successful")

    log.info("Request to finalize the order (all challenges have been completed)")
    log.info(config['csrfile'])
    csr_der = _base64(_openssl("req", ["-in", config['csrfile'],
                                       "-outform", "DER"]))
    log.info(csr_der)
    http_response, result = _send_signed_request(order["finalize"], {"csr": csr_der})
    if http_response.status_code != 200:
        raise ValueError("Error while sending the CSR: {0} {1}"
                         .format(http_response.status_code, result))

    while True:
        http_response, order = _send_signed_request(order_location, "")

        if order["status"] == "processing":
            try:
                time.sleep(float(http_response.headers["Retry-After"]))
            except (OverflowError, ValueError, TypeError):
                time.sleep(2)
        elif order["status"] == "valid":
            log.info("Order finalized!")
            break
        else:
            raise ValueError("Finalizing order {0} got errors: {1}".format(
                order_location, order))

    http_response, result = _send_signed_request(
        order["certificate"], "",
        {'Accept': 'application/pem-certificate-chain'})
    if http_response.status_code != 200:
        raise ValueError("Finalizing order {0} got errors: {1}"
                         .format(http_response.status_code, result))

    if 'link' in http_response.headers:
        log.info("  - Certificate links given by server: %s", http_response.headers['link'])

    log.info("Certificate signed and chain received: %s", order["certificate"])
    log.info(http_response.text)
    log.info(type(http_response.text))
    return http_response.text


def new_csr_comp(domain_name, pkey_pem=None) -> None:
    """Create certificate signing request."""
    if pkey_pem is None:
        # Create private key.
        pkey = OpenSSL.crypto.PKey()
        pkey.generate_key(OpenSSL.crypto.TYPE_RSA, CERT_PKEY_BITS)
        pkey_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM,
                                                  pkey)
    csr_pem = crypto_util.make_csr(pkey_pem, [domain_name])
    with open('/tmp/domain.key', 'wb') as file:
        file.write(pkey_pem) 
    with open('/tmp/domain.csr', 'wb') as file:
        file.write(csr_pem) 


# def main(argv):
def main(mytimer: func.TimerRequest) -> None:
    paramsfileloc =f"./acme/{os.environ['environment']}.parameters.json"
    logger.info(paramsfileloc)
    with open(paramsfileloc,encoding="utf-8") as jsonfile:
        config = json.load(jsonfile)
    logger.info(config)
    check_generate_accountkey(config)
    new_csr_comp(config['certcname'])
    signed_crt = get_crt(config, logger)
    sys.stdout.write(signed_crt)
    with open('/tmp/domain.key', 'r') as file:
        private_key = file.read()
    key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, private_key)
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, signed_crt)
    pkcs = OpenSSL.crypto.PKCS12()
    pkcs.set_privatekey(key)
    pkcs.set_certificate(cert)
    with open('/tmp/cert.pfx', 'wb') as file:
        file.write(pkcs.export())
    upload_certificate_keyvault(config,logger) 

def check_generate_accountkey(config) -> None:
    keyvault = config['keyvaulturl']
    credential = DefaultAzureCredential()
    secret_client = SecretClient(vault_url=keyvault, credential=credential)
    def dump_key_to_a_file(key):
        private_key_str = key.value[2:-1]
        new_string = private_key_str.replace("\\n", "\n")
        with open('/tmp/account.key', 'w') as file:
            file.write(new_string)
    try:
        key = secret_client.get_secret('accountkey')
        dump_key_to_a_file(key)
    except ResourceNotFoundError as e:
        logger.info(e.message)
        #Create key if the key is not there in the specified keyvault
        key = RSA.generate(4096)
        private_key = key.export_key()
        key = secret_client.set_secret('accountkey',private_key)
        dump_key_to_a_file(key)

def upload_certificate_keyvault(config,logger) -> None:
    credential = DefaultAzureCredential()
    keyvault = config['keyvaulturl']
    secret_client = SecretClient(vault_url=keyvault, credential=credential)
    with open('/tmp/cert.pfx', 'rb') as pfx_file:
        pfx_binary_data = pfx_file.read()
    pfx_base64 = base64.b64encode(pfx_binary_data).decode('utf-8')
    response = secret_client.set_secret('certificate',pfx_base64,content_type='application/x-pkcs12',tags={'file-encoding': 'base64'})
    logger.info('Removing the temp files saved')
    if os.path.exists('/tmp'):
        os.remove('/tmp/account.key')
        os.remove('/tmp/domain.key')
        os.remove('/tmp/cert.pfx')
    else:
        logger.info("File path not found")


if __name__ == "__main__":
    main()
