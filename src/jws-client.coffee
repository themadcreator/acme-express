logger = require './logger'

class JwsClient
  # URL-safe base64 encoding
  @toBase64 : (buffer) ->
    return new Buffer(buffer)
      .toString('base64')
      .replace(/\=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')

  constructor : (@accountPrivateKey, @jwsServer) ->
    rsaKey = ursa.createPrivateKey(@accountPrivateKey)
    @jwsHeader = {
      alg : 'RS256'
      jwk :
        'e'   : JwsClient.toBase64(rsaKey.getExponent())
        'kty' : 'RSA'
        'n'   : JwsClient.toBase64(rsaKey.getModulus())
    }

    @thumbprint = JwsClient.toBase64(
      crypto.createHash('sha256')
        .update(JSON.stringify(@jwsHeader.jwk))
        .digest()
    )

  httpRequest : (url, data) ->
    method = if data? then 'post' else 'get'
    logger.debug 'REQUEST:', method, url
    return new Promise((resolve, reject) ->
      request[method]({
        url      : url
        body     : data
        encoding : null
      }, (err, res, body) ->
        if err? then return reject(err)
        res.body = body
        resolve(res)
      )
    )

  jwsRequest : (path, payload) ->
    return @jwsRequestUrl(@jwsServer + path, payload)

  jwsRequestUrl : (url, payload) ->
    return @httpRequest(@jwsServer + '/directory').then (res) =>
      # Protect and sign payload
      nonce        = res.headers['replay-nonce']
      protectedEnc = JwsClient.toBase64(JSON.stringify({nonce : nonce}))
      payloadEnc   = JwsClient.toBase64(JSON.stringify(payload))
      signature    = JwsClient.toBase64(crypto.createSign('RSA-SHA256')
        .update(protectedEnc)
        .update('.')
        .update(payloadEnc)
        .sign(@accountPrivateKey)
      )

      jws = JSON.stringify({
        header    : @jwsHeader
        protected : protectedEnc
        payload   : payloadEnc
        signature : signature
      }, null, 2)

      return @httpRequest(url, jws)

module.exports = {JwsClient}
