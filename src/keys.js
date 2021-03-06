var sjcl = require('sjcl');
var bip39 = require('bip39');
var bitcoin = require('bitcoinjs-lib');
var bigInteger = require('bigi');

var WORDSIZE = 4;  /* 32 bits. */
var ITERCOUNT = 10000;

/**
 * Generate a salt and derive keys based on the username and password given.
 * PBKDF2-HMAC-SHA256 is used for key stretching with a default iteration
 * count of 10000.
 *
 * @param {string} username
 * @param {string} password
 * @param {number} [iters=10000] - Number of iterations for PBKDF2.
 * @param {string} [salt] - Salt as hexadecimal digits.
 * @returns {object}
 */
function deriveKeys(username, password, iters, salt) {
    var saltHex, rawSalt, iterCount;
    var data = username + password;
    var check = checkBytes(data);

    if (salt) {
        rawSalt = sjcl.codec.hex.toBits(salt);
        saltHex = salt;
    } else {
        rawSalt = sjcl.random.randomWords(16 / WORDSIZE);
        saltHex = sjcl.codec.hex.fromBits(rawSalt);
    }

    /* Use PBKDF2-HMAC-SHA256 to generate a base key for usage with BIP39. */
    if (!iters) {
        iterCount = ITERCOUNT + Math.abs(sjcl.random.randomWords(1)[0] % 1024);
    } else {
        iterCount = Math.max(iters, 5000);
    }
    var baseKey = sjcl.misc.pbkdf2(data, rawSalt, iterCount);

    var words = bip39.entropyToMnemonic(keyToBuffer(baseKey));

    var keys = recoverKeys(words);

    return {
        payload: {
            username: username,
            check: check,
            salt: saltHex,
            iterations: iterCount
        },
        key: keys,
        mnemonic: words.toString()
    };
}

/**
 * Produce keys for encrypting, signing requests, and generating wallets
 * from the given words using BIP39.
 *
 * The encrypting key corresponds to the key derived at m/0', the
 * signing key (and the respective public address) at m/1', and
 * m/2' for the wallet gen key which is expected to be further derived
 * for each wallet belonging to the same user.
 *
 * @param {string} mnemonic - a string of words or an instance of Mnemonic.
 * @returns {object}
 */
function recoverKeys(mnemonic) {
    var seed = bip39.mnemonicToSeed(mnemonic, bitcoin.networks.bitcoin);
    var hdMaster = bitcoin.HDNode.fromSeedBuffer(seed);

    var rawEncKey = hdMaster.deriveHardened(0);
    var rawSignKey = hdMaster.deriveHardened(1);
    var rawGenKey = hdMaster.deriveHardened(2);

    var encKey = sjcl.codec.hex.toBits(rawEncKey.keyPair.d.toHex());
    var signKey = rawSignKey;
    var signAddress = rawSignKey.getAddress().toString();

    var wifKey = rawSignKey.keyPair.toWIF();


    return {
        sign: {
            key: signKey,
            wif : wifKey,
            address: signAddress,
            raw: rawSignKey
        },
        encrypt: encKey,
        genWallet: rawGenKey
    };
}

/**
 * Convert data stored as a sequence of 8 elements composed of
 * 4 bytes each to a sequence of bytes as a Buffer.
 *
 * @example
 * ```javascript
 * var bitjws = require('bitjws-js');
 *
 * var data = bitjws.keys.deriveKeys('my username', 'my password');
 * var buffer = bitjws.keys.keyToBuffer(data.key.encrypt);
 * ```
 *
 * @param {array} key - array of length 8
 * @returns {object}
 */
function keyToBuffer(key) {
    var abuffer = new ArrayBuffer(32);  /* 256 bits. */
    var iview = new Int32Array(abuffer);
    var bview = new Uint8Array(abuffer);

    if (iview.length != key.length) {
        throw new Error("Unexpected length");
    }

    for (var i = 0; i < iview.length; i++) {
        iview[i] = key[i];
    }

    return new Buffer(bview);
}


/**
 * Return the last 6 hexadecimal digits from SHA256(data).
 *
 * @param {string} data
 * @returns {string}
 */
function checkBytes(data) {
    var hash = sjcl.hash.sha256.hash(data);
    var hex = sjcl.codec.hex.fromBits(hash);
    var check = hex.slice(-6);
    return check;
}

// /**
//  * Returns in wif format the privateKey provided.
//  *
//  * @param {string} priv
//  * @returns {string}
//  */
// function privToWif(priv) {
//     return bitcore.PrivateKey(priv).toWIF();
// }

// /**
//  * Returns a PrivateKey object from the wif format privateKey provided.
//  *
//  * @param {string} wif
//  * @returns {Object}
//  */
// function wifToPriv(wif) {
//     var pvKey = new bitcore.PrivateKey(wif);
//     return {
//         key: pvKey,
//         address: pvKey.publicKey.toAddress().toString(),
//     }
// }


module.exports = {
  deriveKeys : deriveKeys,
  recoverKeys : recoverKeys,
  keyToBuffer : keyToBuffer,
  checkBytes : checkBytes,
  // privToWif : privToWif,
  // wifToPriv : wifToPriv,
  // bitcore : bitcore,
}
