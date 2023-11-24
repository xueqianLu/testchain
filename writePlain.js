var tdh2 = require('./tdh2')
var request = require('request')
var sm2 = require('./sm2')
var msgpack = require('@msgpack/msgpack')

const date = new Date()
const curTimestamp = date.getTime()
const userid = 1002
const key = "41ad9302dc133e8ec01292b0227c45d90944bd9e8f754d5cbf9cc40a00db8633"
const pubkey = "04e583f6ccf91f0ee6d6c05930a8130b7dca219dacb054786753e7659440f47eeb73907e10e8afc06e916254e673c762740cc46c9cee1aefd97c3d8f2f5182b8a0"

const msg = "12345678"
const WriteInfo = {
    UserID: userid,
    Info: msg,
    Hash: "",
    Acl: [""]
}

const winfoData = msgpack.encode(WriteInfo)
const aa = msgpack.decode(winfoData)

const uid = tdh2.sm3hashStr(msg)
const wreq = { wType: 0, UID: uid, OP: winfoData }
const wreqData = msgpack.encode(wreq)
const bb = msgpack.decode(wreqData)

const clientReq = {
    Type: 7,
    ID: userid,
    OP: wreqData,
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
    "req_data": baseReqData,
    "signature": baseSignature
}

request.post(
    'http://127.0.0.1:11010/chainBrowser/user/usertx/writePlain', { json: form },
    function (error, response, body) {
        if (!error && response.statusCode == 200) {
            console.log(body)
        }
    }
)