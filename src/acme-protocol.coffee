http        = require 'http'
Promise     = require 'bluebird'
chalk       = require 'chalk'
logger      = require './logger'
{JwsClient} = require './jws-client'

class AcmeProtocol
  constructor : (@io) ->

  getCertificate : (domain, certificateDER) ->
    return Promise.resolve()
      .then(@register)
      .then(=> @authorize(domain))
      .then(@challengeResponse)
      .then(=> @sign(certificateDER))

  register : =>
    logger.info chalk.blue '\nRegistering account'
    return @io.jwsRequest('/acme/new-reg', {
      resource  : 'new-reg'
      agreement : 'https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf'
    }).then((res) ->
      switch res.statusCode
        when 201 then logger.info chalk.green 'OK'
        when 409 then logger.info chalk.green 'OK - already registered'
        else throw new Error("Registration failed #{res.statusCode}")
    )

  authorize : (domain) =>
    logger.info chalk.blue "\nAuthorizing domain '#{domain}'"
    return @io.jwsRequest('/acme/new-authz', {
      resource   : 'new-authz'
      identifier :
        type  : 'dns'
        value : domain
    }).then((res) ->
      if res.statusCode isnt 201 then throw new Error("Authorization failed #{res.statusCode}")
      logger.info chalk.green 'OK'
      return JSON.parse(res.body.toString('utf8'))
    )

  challengeResponse : (authorization) =>
    logger.info chalk.blue '\nPerforming challenge/response'

    # Extract HTTP challenge token
    {challenges} = authorization
    challenge = challenges.filter((c) -> c.type is 'http-01')[0]
    if not challenge? then throw new Error('No HTTP challenge available')
    {token} = challenge
    keyAuthorization = "#{token}.#{@io.thumbprint}"

    # Create server to respond to challenge
    wellknownChallengePath = "/.well-known/acme-challenge/#{token}"
    logger.info "  Serving challenge token #{chalk.yellow token}"
    server = http.createServer((req, res)->
      logger.info chalk.yellow '  Got request at token url...'
      if req.url is wellknownChallengePath
        res.statusCode = 200
        res.end(keyAuthorization)
      else
        res.statusCode = 404
        res.end()
    )

    # When server starts, inform CA we are ready for challenge
    server.listen(80, =>
      logger.info '  Listening on port 80'
      @io.jwsRequestUrl(challenge.uri, {
        resource         : 'challenge'
        keyAuthorization : keyAuthorization
      })
    )

    # Poll status every 1 sec until we know if challenge succeeded
    return new Promise((resolve, reject) =>
      pollStatus = =>
        @io.httpRequest(challenge.uri).then((res) ->
          {status} = JSON.parse(res.body.toString('utf8'))
          logger.info "  Challenge status is '#{chalk.yellow status}'..."
          if status isnt 'pending'
            return server.close(->
              logger.info '  Server stopped'
              if status is 'valid'
                logger.info chalk.green 'OK'
                resolve(status)
              else
                reject(new Error("Failed challenge/response with status '#{status}'. Make sure this server is accessible at the domain URL."))
            )
          setTimeout(pollStatus, 1000)
        )

      pollStatus()
    )

  sign : (certificateDER) ->
    logger.info chalk.blue '\nSigning certificate'
    return @io.jwsRequest('/acme/new-cert', {
      resource : 'new-cert'
      csr      : JwsClient.toBase64(certificateDER)
    }).then((res) ->
      if res.statusCode isnt 201 then throw new Error("Signing failed with code #{res.statusCode}")
      logger.info chalk.green 'OK'
      if res.headers.location? then logger.info 'Certificate available for download at', chalk.yellow res.headers.location
      certblock = res.body.toString('base64').replace(/(.{64})/g, '$1\n')
      return """
        -----BEGIN CERTIFICATE-----
        #{certblock}
        -----END CERTIFICATE-----
      """
    )

module.exports = {AcmeProtocol}