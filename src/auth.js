// var Message = require('bitcore-message');
var bitcoin = require('bitcoinjs-lib');
var base64url = require('base64-url');
var bigi = require('bigi');
var bitcoinMessage = require('bitcoinjs-message');
var stringify = require('json-stable-stringify');

/**
 * Return a JWT header base64url encoded. The keyId is stored in the header
 * and used when verifying the signature.
 *
 * @param {keyId} string
 * @returns {string}
 * @private
 */
function jwtHeader(keyId) {
    var data = {
        typ: 'JWT',
        alg: 'CUSTOM-BITCOIN-SIGN',
        kid: keyId
    };

    return base64url.encode(stringify(data));
}

/**
 * Return a signed bitcore.message. By default the expiration claim (exp) is
 * set to one hour in the future and the issued at claim (iat) is the current
 * unix timestamp * 1000.
 *
 * @param {string} url - Used as the audience (aud) in the bitcore.message claims.
 * @param {object} payload - Arbitrary data to be added to the bitcore.message payload.
 * @param {object} sign - An object that contains at least "address" and "key".
 * @returns {string}
 */
function signSerialize(url, data, key, expTime) {

    var exp = (new Date().getTime() / 1000) + 3600;
    if (expTime && expTime > 0) {
        exp = (new Date().getTime() / 1000) + expTime;
    }

    var payload = {
        aud : url,
        data : data,
        exp : Math.floor(Number(+exp) - 0),
        iat : new Date().getTime()
    }

    var rawPayload = base64url.encode(stringify(payload));
    var msg = jwtHeader(key.getAddress().toString()) + '.' + rawPayload;

    var privateKey = key.keyPair.d.toBuffer(32);
    var messagePrefix = bitcoin.networks.bitcoin.messagePrefix;

    var signature = bitcoinMessage.sign(msg, messagePrefix, privateKey, key.keyPair.compressed)
    var signatureEncoded = base64url.encode(signature.toString('base64'))


    return msg + '.' + signatureEncoded;
}


/**
 * Verify a signed signed message and return its address and payload if
 * the signature matches.
 *
 * @param {string} url - Used as the audience (aud) in the JWT claims.
 * @param {string} raw - signed bittcore.message received.
 * @returns {object}
 */
function validateDeserialize(url, raw, checkExpiration) {

    var pieces = raw.split('.');

    if (pieces.length != 3) {
        throw new TypeError("Invalid raw data");
    }

    var rawHeader = pieces[0];
    var rawPayload = pieces[1];
    var signature = base64url.decode(pieces[2]);

    var header = JSON.parse(base64url.decode(rawHeader));
    var key = header.kid;
    var messagePrefix = bitcoin.networks.bitcoin.messagePrefix;

    if (!key) {
        throw new TypeError("Invalid header, missing key id");
    }
    if (!(bitcoinMessage.verify(rawHeader + '.' + rawPayload, messagePrefix, key, signature))) {
        throw new Error("Signature does not match");
    }

    var payload = JSON.parse(base64url.decode(rawPayload));
    if (payload.aud !== url) {
        throw new Error("Audience mismatch (" + payload.aud + " != " + url + ")");
    } else if (checkExpiration && ((new Date().getTime() / 1000) > payload.exp)) {
        throw new Error("Payload expired");
    }

    return {header: header, payload: payload};

}


module.exports = {
  signSerialize : signSerialize,
  validateDeserialize : validateDeserialize,
}
