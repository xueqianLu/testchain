var tdh2 = require('./tdh2')
var request = require('request')
var sm2 = require('./sm2')
var msgpack = require('@msgpack/msgpack')

const date = new Date()
const curTimestamp = date.getTime()
// const userid = 1002
// const key = "41ad9302dc133e8ec01292b0227c45d90944bd9e8f754d5cbf9cc40a00db8633"
// const pubkey = "04e583f6ccf91f0ee6d6c05930a8130b7dca219dacb054786753e7659440f47eeb73907e10e8afc06e916254e673c762740cc46c9cee1aefd97c3d8f2f5182b8a0"
// const userid = 1003
// const key = "9ca6e0fdbbbd7275960559c3495ceac0f9623a1527e6aed48f4d4407eb820973"
// const pubkey = "04be6d0c6cdd5519757c274a16a21cd723e4041fd48f31bd26de9d2ece8641363db366dc6d90caebabb0c36e0c76b48d40fd65709839293e7d26eacea4b298f015"
// const tdh2pubkey = "{\"Group\":\"P256\",\"G_bar\":\"BOO26Sw3tRlN1xaaA2X90DBFTDGU95nfZTcv8CTUHHEOMkoa2AW1UZQFfH94Kyjus6qj+b8XzEq0B0T1WuGzzUQ=\",\"H\":\"BByFt5mg+YAiYEpFPC5EeEmgS+r2hdZ1Gmp9MZNtOtHjlPqkwbQjn67gmjNfUpY5C98hBMOhrjddH1Ig90ND/vE=\",\"HArray\":[\"BByFt5mg+YAiYEpFPC5EeEmgS+r2hdZ1Gmp9MZNtOtHjlPqkwbQjn67gmjNfUpY5C98hBMOhrjddH1Ig90ND/vE=\",\"BByFt5mg+YAiYEpFPC5EeEmgS+r2hdZ1Gmp9MZNtOtHjlPqkwbQjn67gmjNfUpY5C98hBMOhrjddH1Ig90ND/vE=\",\"BByFt5mg+YAiYEpFPC5EeEmgS+r2hdZ1Gmp9MZNtOtHjlPqkwbQjn67gmjNfUpY5C98hBMOhrjddH1Ig90ND/vE=\",\"BByFt5mg+YAiYEpFPC5EeEmgS+r2hdZ1Gmp9MZNtOtHjlPqkwbQjn67gmjNfUpY5C98hBMOhrjddH1Ig90ND/vE=\"]}"

const userid = 7581048617783297
const key = "76886edd4f20dbfaaea9be12a45f92bb0df47e03584d23e8342bb84f60ae271b"
const pubkey = "04280d4fc730b63f32218991f242f5fc74e846e8ef30999e541584f5a65412f5cf471773fb58d275185d6cc5dbc8f0d92f6079f61c2c467fada2560450ff432f49"
const tdh2pubkey = "{\"Group\":\"P256\",\"G_bar\":\"BOO26Sw3tRlN1xaaA2X90DBFTDGU95nfZTcv8CTUHHEOMkoa2AW1UZQFfH94Kyjus6qj+b8XzEq0B0T1WuGzzUQ=\",\"H\":\"BByFt5mg+YAiYEpFPC5EeEmgS+r2hdZ1Gmp9MZNtOtHjlPqkwbQjn67gmjNfUpY5C98hBMOhrjddH1Ig90ND/vE=\",\"HArray\":[\"BByFt5mg+YAiYEpFPC5EeEmgS+r2hdZ1Gmp9MZNtOtHjlPqkwbQjn67gmjNfUpY5C98hBMOhrjddH1Ig90ND/vE=\",\"BByFt5mg+YAiYEpFPC5EeEmgS+r2hdZ1Gmp9MZNtOtHjlPqkwbQjn67gmjNfUpY5C98hBMOhrjddH1Ig90ND/vE=\",\"BByFt5mg+YAiYEpFPC5EeEmgS+r2hdZ1Gmp9MZNtOtHjlPqkwbQjn67gmjNfUpY5C98hBMOhrjddH1Ig90ND/vE=\",\"BByFt5mg+YAiYEpFPC5EeEmgS+r2hdZ1Gmp9MZNtOtHjlPqkwbQjn67gmjNfUpY5C98hBMOhrjddH1Ig90ND/vE=\"]}"




var pub = JSON.parse(tdh2pubkey)
const txid = "6ea9a640dbb36c29b16f7d2f45c990c753d1f1468433009d5906cd8bb9f11608"
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
    //'http://127.0.0.1:11010/chainBrowser/user/usertx/readCipher', { json: form },
    'http://47.104.157.94:11010/chainBrowser/user/usertx/readCipher', { json: form },
    // 'http://52.221.177.10:11010/chainBrowser/user/usertx/readCipher', { json: form },
    function (error, response, body) {
        if (!error && response.statusCode == 200) {
            console.log(body)
            if (body.code == 0) {
                data = body.data
                c = data.c
                c_little = data.c_little
                nodenum = data.nodenum
                entries = data.shares
                console.log("c: " + c)
                console.log("c_little: " + c_little)
                console.log("shares: " + entries)

                let dr_list = new Array(nodenum).fill(null)
                let dr_count = 0
                entries.forEach(strentry => {
                    const entry = JSON.parse(strentry)
                    const index = entry.replica_id
                    const dr = sm2.decrypt(entry.share.substring(2), key, 1)
                    if (dr.length != 0) {
                        dr_list[index] = JSON.parse(dr)
                        dr_count++
                    }
                })
                // set dr_list to dr_list[0:dr_count]
                // dr_list = dr_list.slice(0, dr_count)
                let ndr = new Array()
                for (let i = 0; i < dr_list.length; i++) {
                    if (dr_list[i] != null) {
                        ndr.push(dr_list[i])
                    }
                }
                dr_list = ndr


                const cipher = JSON.parse(c_little)
                for (let i = 0; i < dr_list.length; i++) {
                    console.log("Verify share--", i, "------", tdh2.verify_share(cipher, pub, dr_list[i]))
                }
                let key_TDH2 = tdh2.combine_Share(pub, cipher, dr_list, parseInt(nodenum / 3) + 1)

                let decmsg = tdh2.decrypt_SM4(key_TDH2, cipher)
                console.log("decmsg: " + decmsg)
            }


        }
    }
)