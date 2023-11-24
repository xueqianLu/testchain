const sm2 = require('sm-crypto').sm2

function keygen() {
    let keypair = sm2.generateKeyPairHex(),
        publicKey = keypair.publicKey, // 公钥
        privateKey = keypair.privateKey // 私钥

    return {
        PK: publicKey,
        SK: privateKey
    }
}

function recover(sk) {
    return sm2.getPublicKeyFromPrivateKey(sk)
}

function encrypt(msgString, publicKey, cipherMode) {

    return sm2.doEncrypt(msgString, publicKey, cipherMode)

}

function decrypt(encryptData, privateKey, cipherMode) {
    return sm2.doDecrypt(encryptData, privateKey, cipherMode)
}

function sign(msg, privateKey) {
    return sm2.doSignature(msg, privateKey, { hash: true })
}

function sign2(msg, privateKey) {
    return sm2.doSignature(msg, privateKey, { hash: false })
}

function verify(msg, sigValueHex, publicKey) {
    return sm2.doVerifySignature(msg, sigValueHex, publicKey, { hash: true })
}

function verify2(msg, sigValueHex, publicKey) {
    return sm2.doVerifySignature(msg, sigValueHex, publicKey, { hash: false })
}
// msg: 840547970657049440300050067830775479706500554944040366530663965313433343463353430366130636635613362346466623636356638376634613737316133316637656462623563373238373461333262323935370050014820757365724944030069066003132330545300010009579
module.exports = { keygen, encrypt, decrypt, sign, sign2, verify, verify2, recover }