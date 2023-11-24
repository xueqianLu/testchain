var msgpack = require('@msgpack/msgpack')
const winfo = {
    UserID: 1002,
    Info: "123456",
}
var arr = msgpack.encode(winfo)
console.log(Buffer.from(arr).toString('hex'))

function arrayToHex1 (arr) {
    return arr.map(item => {
        item = item.toString(16)
        return item.length === 1 ? '0' + item : item
    }).join('')
}

function arrayToHex2 (arr) {
    return arr.reduce((output, elem) =>
        (output + ('0' + elem.toString(16)).slice(-2)),
        '')
}
console.log(arrayToHex1(Array.prototype.slice.call(arr)))
console.log("hex1", arrayToHex1(arr))
console.log("hex2", arrayToHex2(arr))