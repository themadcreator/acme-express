crypto  = require 'crypto'
http    = require 'http'
https   = require 'https'
asn1    = require 'asn1.js'
Promise = require 'bluebird'
logger  = require './logger'

class JwsClient
  # URL-safe base64 encoding
  @toBase64 : (buffer) ->
    return new Buffer(buffer)
      .toString('base64')
      .replace(/\=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')

  @rsaEncoding : asn1.define 'RSA PRIVATE KEY', ->
    @seq().obj(
      @key('version').int()
      @key('modulus').int()
      @key('publicExponent').int()
      @key('privateExponent').int()
      @key('prime1').int()
      @key('prime2').int()
      @key('exponent1').int()
      @key('exponent2').int()
      @key('coefficient').int()
    )

  constructor : (@accountPrivateKey, @jwsServer) ->
    rsaKey = JwsClient.rsaEncoding.decode(@accountPrivateKey, 'pem', {label : JwsClient.rsaEncoding.name})
    @jwsHeader = {
      alg : 'RS256'
      jwk :
        'e'   : JwsClient.toBase64(rsaKey.publicExponent.toArray())
        'kty' : 'RSA'
        'n'   : JwsClient.toBase64(rsaKey.modulus.toArray())
    }

    @thumbprint = JwsClient.toBase64(
      crypto.createHash('sha256')
        .update(JSON.stringify(@jwsHeader.jwk))
        .digest()
    )

  httpRequest : (url, data) ->
    logger.debug 'REQUEST:', url, data

    # Parse URL and add headers
    options = require('url').parse(url)
    if data?
      options.method  = 'POST'
      options.headers = {
        'content-length' : Buffer.byteLength(data)
      }
    request = if options.protocol is 'https:' then https.request else http.request
    
    # Return request promise
    return new Promise((resolve, reject) ->
      req = request(options, (res) ->
        chunks = []
        res.setEncoding(null)
        res.on 'data', (d) -> chunks.push(new Buffer(d))
        res.on 'end', ->
          res.body = Buffer.concat(chunks)
          resolve(res)
      )
      req.on 'error', (err) -> reject(err)
      if data? then req.write(data)
      req.end()
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
