const sm3 = require('sm-crypto').sm3
const sm4 = require('sm-crypto').sm4

function sm3hash (buffermsg) {
    let string_buffermsg = buffermsg.toString('base64')
    return Buffer.from(sm3(string_buffermsg), "hex")
}


function sm3hashStr (buffermsg) {
    let string_buffermsg = buffermsg.toString('base64')
    return sm3(string_buffermsg)
}

function encrypt_sm4 (msg, key_tdh2) {

    const blockSize = 16
    const key_SM4 = key_tdh2.substring(0, 16)
    const real_key_SM4 = keyToAsciiArray(key_SM4)
    if (msg.length > ((2 ** 32) - 2) * blockSize)
        throw new Error('message too long')
    const ctxt = sm4.encrypt(msg, real_key_SM4)
    return ctxt
}

function keyToAsciiArray (key) {
    const asciiArray = []
    for (let i = 0; i < key.length; i++) {
        asciiArray.push(key.charCodeAt(i))
    }
    return asciiArray
}

h1 = sm3hashStr("12345678")
h2 = sm3hashStr(h1)
enc = encrypt_sm4("0b747673b3879014365fd48c584b9d175a252bdfbbc7d1cbb3b885e9ba2c6e7d", h2)
console.log(enc)