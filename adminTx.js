var request = require('request')
var sm2 = require('./sm2')
var msgpack = require('@msgpack/msgpack')

const date = new Date()
const curTimestamp = date.getTime()

const adminUserId = 999
const adminPrivateKey = "4911e4dde41cd26c86648b1b6ad711ae4e65ea7d30541fef879184e95591e50d"
const adminPublicKey = "04c11608dec7ee50f4270da0375cc19ac10685877a522532d28204b36812d72e6ce576db7755744419573e5f9ae62081155fca0b5b496587e992d313778fc137c0"

const userid = 1002
const user_pubkey = "04e583f6ccf91f0ee6d6c05930a8130b7dca219dacb054786753e7659440f47eeb73907e10e8afc06e916254e673c762740cc46c9cee1aefd97c3d8f2f5182b8a0"

const AdminRequest = {
    UserID: userid,
    Type: 1, // 1: 冻结用户 2: 解冻账户 3: 注销账户 
    // Type: 1, // 1: 冻结用户 2: 解冻账户 3: 注销账户 
}

const reqData = msgpack.encode(AdminRequest)

const clientReq = {
    Type: 12,
    ID: adminUserId,
    OP: reqData,
    TS: curTimestamp,
}

const clientReqData = msgpack.encode(clientReq)
const signature = sm2.sign(Array.prototype.slice.call(clientReqData), adminPrivateKey)
const baseReqData = Buffer.from(clientReqData).toString('base64')
const baseSignature = Buffer.from(signature, 'HEX').toString('base64')

const form = {
    // "user_id": adminUserId,
    // "pubkey": adminPublicKey,
    "req_data": baseReqData,
    "signature": baseSignature
}

request.post(
    // 'http://127.0.0.1:11010/chainBrowser/user/usertx/adminTx', { json: form },
    'http://52.221.177.10:11010/chainBrowser/user/usertx/adminTx', { json: form },
    function (error, response, body) {
        if (!error && response.statusCode == 200) {
            console.log(body)
        }
    }
)