fs             = require 'fs'
commander      = require 'commander'
logger         = require './logger'

BASENAME = require('path').basename(process.argv[1])

CERTIFICATE_AUTHORITIES = {
  'letsencrypt-staging' : 'https://acme-staging.api.letsencrypt.org'
  'letsencrypt-beta'    : 'https://acme-v01.api.letsencrypt.org'
}

CERTIFICATE_AGREEMENTS = {
  'letsencrypt-1.0.1' : 'https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf'
}

lookupOrUrl = (obj) ->
  return (key) ->
    if (val = obj[key])? then return val
    else if (/^https/.test(key)) then return val
    else throw new Error("Unknown option '#{key}'")

commander
  .usage("""--account account.pem --csr domain.der --domain ${DOMAIN} --ca letsencrypt-staging
  \n
    ACME protocol client for automated signed x.509 certificates.

    Letsencrypt.org is an EFF-sponsored, *gratis* service that implements the
    ACME protocol. This script will allow you to create a signed x.509
    certificate, suitable to secure your server with HTTPS, using
    letsencrypt.org or any other certificate authority that supports the ACME
    protocol.
  """)
  .description("""
  \n  
    ## Sign a cert
    
    Register a domain, point your DNS at your server. From that server, you
    can use this script to verify that you control the domain and acquire a
    signed certficate.

    ```bash
      # Set your domain
      export DOMAIN=mydomain.org

      # Create domain key and DER encoded Certificate Signing request
      openssl genrsa 4096 > domain.pem
      openssl req -new -sha256 -key domain.pem -subj "/CN=${DOMAIN}" -outform DER > domain.der

      # Create account key and get letsencrypt.org to sign your cert
      openssl genrsa 4096 > account.pem
      sudo #{BASENAME} --account account.pem --csr domain.der --dom "${DOMAIN}" --ca letsencrypt-beta > cert.pem
    ```

    #### Why Sudo?

    To verify ownership of the domain, we use the simple HTTP
    challenge/response method. This script will briefly host a Node.js HTTP
    server on port 80 (which requires admin access). The challenge token is
    served at the well-defined challenge/response URL so that the certificate
    authority can request it.

    See the "challengeResponse" method in src/acme-protocol.coffee

    ## Create an HTTPS Server

    Here is a simple Node.js express server using the certificate produced by
    this script:

    ```javascript
      let fs      = require('fs');
      let http    = require('http');
      let https   = require('https');
      let express = require('express');
      let app     = express();
      let domain  = 'mydomain.org';

      // Load the HTTPS credentials
      let credentials = {
        key  : fs.readFileSync('domain.pem'),
        cert : fs.readFileSync('cert.pem'),

        // If you want to get an 'A' on your ssllabs report card, you need to
        // include the cross-signed cert from letsencrypt.org. You can get a
        // copy with the following command:
        //   #{BASENAME} --cross-signed > lets-encrypt-x1-cross-signed.pem
        // Or, you can download it directly from letsencrypt.org at the following URL:
        //   https://letsencrypt.org/certs/lets-encrypt-x1-cross-signed.pem
        ca   : [fs.readFileSync('lets-encrypt-x1-cross-signed.pem')]
      }

      // Create an HTTPS server with your express app
      https.createServer(credentials, app).listen(443, function() {
        console.log('Listening on HTTPS');
      });

      // (Optional) Create a simple server to redirect all HTTP traffic to HTTPS
      http.createServer(function (req, res) {
        let code = (req.method === 'POST') ? 307 : 302;
        res.writeHead(code, {'Location' : 'https://' + domain + req.url});
        res.end();
      }).listen(80, function() {
        console.log('Redirecting HTTP to HTTPS');
      });
    ```
  """)
  .option('--cross-signed', 'Print letsencrypt.org\'s cross-signed x1 cert to STDOUT')
  .option('--account <account.pem>', 'Account private key PEM file', fs.readFileSync)
  .option('--csr <domain.der>', 'Certificate Signing Request file in DER encoding', fs.readFileSync)
  .option('--dom <domain>', 'The domain for which we are requesting a certificate. E.g. "mydomain.org"')
  .option('--ca [URL|"letsencrypt-beta"|"letsencrypt-staging"]', 'Certificate authority URL running ACME protocol. Default "letsencrypt-staging"', lookupOrUrl(CERTIFICATE_AUTHORITIES), CERTIFICATE_AUTHORITIES['letsencrypt-staging'])
  .option('--agreement [URL|"letsencrypt-1.0.1"]', 'The certificate agreement URL. Default "letsencrypt-1.0.1"', lookupOrUrl(CERTIFICATE_AGREEMENTS), CERTIFICATE_AGREEMENTS['letsencrypt-1.0.1'])
  .option('--log [debug|info|warn|error]', 'Set the log level (logs always use STDERR). Default "info"', 'info')

do ->
  options = commander.parse(process.argv)

  if options.crossSigned
    console.log fs.readFileSync(__dirname + '/lets-encrypt-x1-cross-signed.pem', 'utf-8')
    return

  {JwsClient}    = require './jws-client'
  {AcmeProtocol} = require './acme-protocol'

  # Check args
  if not (options.account? and options.csr? and options.dom?) then return commander.help()


  # Set log level
  logger.setLevel(options.log)

  # Get certificate
  acme = new AcmeProtocol(new JwsClient(options.account, options.ca))
  acme.getCertificate(options.dom, options.csr)
    .then((cert) -> console.log cert) # Output signed cert to STDOUT
    .catch((err) ->
      log.error(err)
      process.exit(1)
    )