var tdh2 = require('./tdh2')
var request = require('request')
var sm2 = require('./sm2')
var msgpack = require('@msgpack/msgpack')

const date = new Date()
const curTimestamp = date.getTime()
const userid = 1002
const key = "41ad9302dc133e8ec01292b0227c45d90944bd9e8f754d5cbf9cc40a00db8633"
const pubkey = "04e583f6ccf91f0ee6d6c05930a8130b7dca219dacb054786753e7659440f47eeb73907e10e8afc06e916254e673c762740cc46c9cee1aefd97c3d8f2f5182b8a0"
// userid 1003 pubkey
const pubkey_friend = "04be6d0c6cdd5519757c274a16a21cd723e4041fd48f31bd26de9d2ece8641363db366dc6d90caebabb0c36e0c76b48d40fd65709839293e7d26eacea4b298f015"
const txid = ""
const WriteInfo = {
    UserID: userid,
    Txid: txid,
    Acl: [pubkey_friend]
}

const winfoData = msgpack.encode(WriteInfo)
const aa = msgpack.decode(winfoData)

const uid = userid.toString('hex')
const wreq = { WType: 3, UID: uid, OP: winfoData }
const wreqData = msgpack.encode(wreq)

const clientReq = {
    Type: 7,
    ID: userid,
    OP: wreqData,
    TS: curTimestamp,
}
const clientReqData = msgpack.encode(clientReq)
const signature = sm2.sign(Array.prototype.slice.call(clientReqData), key)
const baseReqData = Buffer.from(clientReqData).toString('base64')
const baseSignature = Buffer.from(signature, 'HEX').toString('base64')

const form = {
    "user_id": userid,
    "pubkey": pubkey,
    "req_data": baseReqData,
    "signature": baseSignature
}

request.post(
    // 'http://127.0.0.1:11010/chainBrowser/user/usertx/deleteACL', { json: form },
    'http://52.221.177.10:11010/chainBrowser/user/usertx/deleteACL', { json: form },
    function (error, response, body) {
        if (!error && response.statusCode == 200) {
            console.log(body)
        }
    }
)