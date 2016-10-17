var keys = require('./src/keys');
var auth = require('./src/auth');

module.exports = {
    signSerialize : auth.signSerialize,
    validateDeserialize : auth.validateDeserialize,
    deriveKeys : keys.deriveKeys,
    recoverKeys : keys.recoverKeys,
    keyToBuffer : keys.keyToBuffer,
    checkBytes : keys.checkBytes,
    privToWif : keys.privToWif,
    wifToPriv : keys.wifToPriv,
    bitcore : keys.bitcore,
}
