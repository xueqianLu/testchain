var tdh2 = require('./tdh2')
var request = require('request')
var sm2 = require('./sm2')
var msgpack = require('@msgpack/msgpack')

const date = new Date()
const curTimestamp = date.getTime()
const userid = 1002
const key = "41ad9302dc133e8ec01292b0227c45d90944bd9e8f754d5cbf9cc40a00db8633"
const pubkey = "04e583f6ccf91f0ee6d6c05930a8130b7dca219dacb054786753e7659440f47eeb73907e10e8afc06e916254e673c762740cc46c9cee1aefd97c3d8f2f5182b8a0"

const txid = "ff8a656426f04de186f95ce6f5c6875833e25940111898aba79bb6807938325e"
const readInfo = {
    RType: "4",
    TS: curTimestamp,
    TxID: txid,
}

const readData = msgpack.encode(readInfo)

const clientReq = {
    Type: 8,
    ID: userid,
    OP: Buffer.from(readData),
    TS: curTimestamp,
}
const clientReqData = msgpack.encode(clientReq)
console.log(clientReqData.toString())
const signature = sm2.sign(clientReqData, key)
const baseReqData = Buffer.from(clientReqData).toString('base64')
const baseSignature = Buffer.from(signature, 'HEX').toString('base64')

const form = {
    // "user_id": userid,
    // "pubkey": pubkey,
    "req_data": baseReqData, // 序列化 clientRequest 之后，msg的base64编码值
    "signature": baseSignature, // 前端对msg签名之后，签名值的base64编码值
    "acl": [""], // 可访问密文的公钥列表
    "clittle": "", // 计算过程中生成的小c
    "cipher": "", // 计算过程中生成的大C
    "hash_cipher": "" // cipher 的sm3哈希值
}

request.post(
    'http://127.0.0.1:11010/chainBrowser/user/usertx/writeCipher', { json: form },
    function (error, response, body) {
        if (!error && response.statusCode == 200) {
            console.log(body)
        }
    }
)