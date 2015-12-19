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
    logger.info 'Registering account'
    return @io.jwsRequest('/acme/new-reg', {
      resource  : 'new-reg'
      agreement : 'https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf'
    }).then((res) ->
      switch res.statusCode
        when 201 then logger.info 'OK'
        when 409 then logger.info 'OK - already registered'
        else throw new Error("Registration failed #{res.statusCode}")
    )

  authorize : (domain) =>
    logger.info 'Authorizing domain', domain
    return @io.jwsRequest('/acme/new-authz', {
      resource   : 'new-authz'
      identifier :
        type  : 'dns'
        value : domain
    }).then((res) ->
      if res.statusCode isnt 201 then throw new Error("Authorization failed #{res.statusCode}")
      logger.info 'OK'
      return JSON.parse(res.body.toString('utf8'))
    )

  challengeResponse : (authorization) =>
    logger.info 'Performing challenge/response'

    # Extract HTTP challenge token
    {challenges} = authorization
    challenge = challenges.filter((c) -> c.type is 'http-01')[0]
    if not challenge? then throw new Error('No HTTP challenge available')
    {token} = challenge
    keyAuthorization = "#{token}.#{@io.thumbprint}"

    # Create server to respond to challenge
    logger.info "Creating temporary server with token #{token}..."
    server = http.createServer((req, res)->
      logger.info 'Got request at token url...'
      if req.url is "/.well-known/acme-challenge/#{token}"
        res.statusCode = 200
        res.end(keyAuthorization)
      else
        res.statusCode = 404
        res.end()
    )

    # When server starts, inform CA we are ready for challenge
    server.listen(80, =>
      logger.info 'Challenge/response server listening on port 80...'
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
          logger.info "Challenge status is '#{status}'..."
          if status isnt 'pending'
            return server.close(->
              logger.info 'Challenge/response server stopped...'
              if status is 'valid'
                logger.info 'OK'
                resolve(status)
              else
                reject(status)
            )
          setTimeout(pollStatus, 1000)
        )

      pollStatus()
    )

  sign : (certificateDER) ->
    logger.info 'Signing certificate'
    return @io.jwsRequest('/acme/new-cert', {
      resource : 'new-cert'
      csr      : JwsClient.toBase64(certificateDER)
    }).then((res) ->
      if res.statusCode isnt 201 then throw new Error("Signing failed #{res.statusCode}")
      logger.info 'OK'
      certblock = res.body.toString('base64').replace(/(.{64})/g, '$1\n')
      return """
        -----BEGIN CERTIFICATE-----
        #{certblock}
        -----END CERTIFICATE-----
      """
    )

module.exports = {AcmeProtocol}