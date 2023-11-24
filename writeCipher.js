var tdh2 = require('./tdh2')
var request = require('request')
var sm2 = require('./sm2')
var msgpack = require('@msgpack/msgpack')
var sm3 = require('sm-crypto').sm3
const date = new Date()
const curTimestamp = date.getTime()
const userid = 1002
const key = "41ad9302dc133e8ec01292b0227c45d90944bd9e8f754d5cbf9cc40a00db8633"
const pubkey = "04e583f6ccf91f0ee6d6c05930a8130b7dca219dacb054786753e7659440f47eeb73907e10e8afc06e916254e673c762740cc46c9cee1aefd97c3d8f2f5182b8a0"

const msg = "this is test cipher tx 7."
const tdh2pubkey = "{\"Group\":\"P256\",\"G_bar\":\"BOO26Sw3tRlN1xaaA2X90DBFTDGU95nfZTcv8CTUHHEOMkoa2AW1UZQFfH94Kyjus6qj+b8XzEq0B0T1WuGzzUQ=\",\"H\":\"BByFt5mg+YAiYEpFPC5EeEmgS+r2hdZ1Gmp9MZNtOtHjlPqkwbQjn67gmjNfUpY5C98hBMOhrjddH1Ig90ND/vE=\",\"HArray\":[\"BByFt5mg+YAiYEpFPC5EeEmgS+r2hdZ1Gmp9MZNtOtHjlPqkwbQjn67gmjNfUpY5C98hBMOhrjddH1Ig90ND/vE=\",\"BByFt5mg+YAiYEpFPC5EeEmgS+r2hdZ1Gmp9MZNtOtHjlPqkwbQjn67gmjNfUpY5C98hBMOhrjddH1Ig90ND/vE=\",\"BByFt5mg+YAiYEpFPC5EeEmgS+r2hdZ1Gmp9MZNtOtHjlPqkwbQjn67gmjNfUpY5C98hBMOhrjddH1Ig90ND/vE=\",\"BByFt5mg+YAiYEpFPC5EeEmgS+r2hdZ1Gmp9MZNtOtHjlPqkwbQjn67gmjNfUpY5C98hBMOhrjddH1Ig90ND/vE=\"]}"

var pub = JSON.parse(tdh2pubkey)

const result = tdh2.encrypt(pub, msg)
const hash_C = sm3(Buffer.from(result.ctxt, 'hex'))
const hash_C_str = hash_C.toString('base64')

const WriteInfo = {
    UserID: userid,
    Info: result.jsonString,
    Hash: hash_C_str,
    Acl: [pubkey,]
}

const winfoData = msgpack.encode(WriteInfo)
const uid = hash_C_str

const wreq = { WType: 1, UID: uid, OP: Buffer.from(winfoData) }

const wreqData = msgpack.encode(wreq)

const clientReq = {
    Type: 7,
    ID: userid,
    OP: Buffer.from(wreqData),
    TS: curTimestamp,
}
const clientReqData = msgpack.encode(clientReq)
const signature = sm2.sign(clientReqData, key)
const baseReqData = Buffer.from(clientReqData).toString('base64')
const baseSignature = Buffer.from(signature, 'HEX').toString('base64')

const form = {
    "user_id": userid,
    "pubkey": pubkey,
    "req_data": baseReqData, // 序列化 clientRequest 之后，msg的base64编码值
    "signature": baseSignature, // 前端对msg签名之后，签名值的base64编码值
    "acl": WriteInfo.Acl, // 可访问密文的公钥列表
    "clittle": result.jsonString, // 计算过程中生成的小c
    "cipher": Buffer.from(result.ctxt, 'hex').toString('base64'), // 计算过程中生成的大C
    "hash_cipher": hash_C_str, // cipher 的sm3哈希值
}

request.post(
    'http://127.0.0.1:11010/chainBrowser/user/usertx/writeCipher', { json: form },
    function (error, response, body) {
        if (!error && response.statusCode == 200) {
            console.log(body)
        }
    }
)