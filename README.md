# acme-express

[Automatic Certificate Management Environment](https://github.com/ietf-wg-acme/acme)
(ACME) protocol client for acquiring free SSL certificates.

[Letsencrypt.org](https://letsencrypt.org/) is a gratis, open source community sponsored service that
implements the ACME protocol. This script will allow you to create a
signed SSL certificate, suitable to secure your server with HTTPS, using
letsencrypt.org or any other certificate authority that supports the ACME
protocol.

## Installation

```bash
  npm install -g acme-express
```

## CLI

```
  Usage: acme-express --account account.pem --csr csr.der --domain ${DOMAIN} --ca letsencrypt-beta

  Options:

    -h, --help                                           output usage information
    --account <account.pem>                              Account private key PEM file
    --csr <csr.der>                                      Certificate Signing Request file in DER encoding
    --dom <domain>                                       The domain for which we are requesting a certificate. e.g. "mydomain.org"
    --ca <URL|"letsencrypt-beta"|"letsencrypt-staging">  Certificate authority URL running ACME protocol. Default "letsencrypt-staging"
    --agreement <URL|"letsencrypt-1.0.1">                The certificate agreement URL. Default "letsencrypt-1.0.1"
    --log <debug|info|warn|error>                        Set the log level (logs always use STDERR). Default "info"
    --cross-signed                                       Print letsencrypt.org's cross-signed x1 cert to STDOUT
```

## How to Use

1. Register a domain and point your DNS at your server.
2. From that server, use this script to verify that you control the domain
and acquire a signed certficate.

## Sign a Cert

```bash
  # Set your domain
  DOMAIN=mydomain.org

  # Create domain key and DER encoded Certificate Signing request
  openssl genrsa 4096 > domain.pem
  openssl req -new -sha256 -key domain.pem -subj "/CN=${DOMAIN}" -outform DER > csr.der

  # Create account key and get letsencrypt.org to sign your cert
  openssl genrsa 4096 > account.pem
  sudo acme-express --account account.pem --csr csr.der --dom "${DOMAIN}" --ca letsencrypt-beta > ${DOMAIN}.pem

  # (Optional) Examine your new certificate
  openssl x509 -in ${DOMAIN}.pem -text
```

#### Why Sudo?

To verify ownership of the domain, we use the simple HTTP
challenge/response method. This script will briefly host a Node.js HTTP
server on port 80 (which requires admin access). The challenge token is
served at the well-defined challenge/response URL so that the certificate
authority can request it.

See the "challengeResponse" method in src/acme-protocol.coffee

## Create an HTTPS Server

Here is an example Node.js express server using a certificate produced
by this script:

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
    cert : fs.readFileSync(domain + '.pem'),

    // If you want to get an 'A' on your ssllabs report card, you need to
    // include the cross-signed cert from letsencrypt.org. Download it
    // directly from letsencrypt.org at the following URL:
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
