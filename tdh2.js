const rnd = require('bcrypto/lib/random')
const elliptic = require('bcrypto/lib/js/elliptic')
const cipher = require('bcrypto/lib/cipher')
const sm3 = require('sm-crypto').sm3
const sm4 = require('sm-crypto').sm4
const crypto = require('crypto')

const {
  ShortCurve,
  EdwardsCurve,
  curves
} = elliptic

const {
  Cipher,
  Decipher,
  enc,
  dec
} = cipher


class PloyShare {
  constructor(I, V) {
    this.I = I
    this.V = V
  }
}

class PrivShare {
  constructor(I, V) {
    this.I = I
    this.V = V
  }
}

// public key
class Pub {
  constructor(Group, g, g_bar, h) {
    this.Group = Group
    this.g = g
    this.g_bar = g_bar
    this.h = h
  }
}

class Verikey {
  constructor(Pub, HArray) {
    this.Pub = Pub
    this.tuple = HArray
  }
}
// private key
class Priv {
  constructor(Pub, index, value) {
    this.Pub = Pub
    this.i = index
    this.xi = value
  }
}

class Decrypt_result {
  constructor(index, u_i, e_i, f_i) {
    this.i = index
    this.u_i = u_i
    this.e_i = e_i
    this.f_i = f_i
  }
}

class DH_triple {
  constructor(u, h_i, u_i) {
    this.u = u
    this.h_i = h_i
    this.u_i = u_i
  }
}


const p256 = new curves.P256()
const groupName = "P256"
const tdh2InputSize = 32

function toHexString (byteArray) {
  return Array.from(byteArray, function (byte) {
    return ('0' + (byte & 0xFF).toString(16)).slice(-2)
  }).join('')
}


function sm3hash (buffermsg) {
  //string_buffermsg = buffermsg.toString('base64')
  // string_buffermsg = buffermsg.toString('utf-8')
  string_buffermsg = buffermsg.toString('base64')
  //console.log("1###", string_buffermsg)
  //console.log("2###", string_buffermsg2)
  return Buffer.from(sm3(string_buffermsg), "hex")
}

function GenerateKeys (ms, k, n) {
  if (k > n) {
    throw new Error("marshaling G_bar")
  }
  if (k <= 0) {
    throw new Error("threshold has to be positive")
  }
  if (ms == null) {
    throw new Error("inconsistent groups")
  }

  // const s = p256.randomScalar(rnd)
  let s = ms
  const array = new Array(k)
  let poly = newPoly(k, s)
  let x = poly[0]

  // if (ms != null && !x.equals(ms)) {
  //   throw new Error("generated wrong secret")
  // }

  // elliptic points HArray
  let HArray = Array(n)
  let shares = ployShare(poly, n)
  // privShares := []*PrivateShare{}
  // IDs are assigned consecutively from 0.
  for (let i = 0; i < shares.length; i++) {
    if (i !== shares[i].I) {
      throw new Error("share index, expect")
    }
    HArray[i] = p256.g.mul(shares[i].V)
    // grp.Point().Mul(s.V, nil)
    // privShares = append(privShares, &PrivateShare{grp, s.I, s.V})
  }
  let h = p256.g.mul(x)

  // generate key
  let pub_key = new Pub(groupName, p256.g, p256.randomPoint(rnd), h)
  let verify_key = new Verikey(pub_key, HArray)
  let sk_list = Array(n)
  for (let i = 0; i < sk_list.length; i++) {
    sk_list[i] = new Priv(pub_key, shares[i].I, shares[i].V)
  }

  return {
    PK: pub_key,
    VK: verify_key,
    SK_list: sk_list
  }
}

// Eval computes the private share v = p(i).
function Eval (i, poly) {
  let xi = p256.scalar().fromNumber(1 + i, 'be')
  let v = p256.scalar().fromNumber(0, 'be')

  for (let j = poly.length - 1; j >= 0; j--) {
    v = v.mul(xi)
    v = v.add(poly[j])
  }

  return new PloyShare(i, v)
}

function ployShare (poly, n) {
  let shares = Array(n)
  for (let i = 0; i < shares.length; i++) {
    shares[i] = Eval(i, poly)
  }
  return shares
}


function newPoly (t, s) {
  const array = new Array(t)
  if (s !== 0) {
    array[0] = s
  } else {
    array[0] = p256.randomScalar(rnd)
  }
  for (let i = 1; i < t; i++) {
    array[i] = p256.randomScalar(rnd)
  }
  return array
}

// Combine share
function Combine (share_list, t) {
  if (share_list.length < t + 1) {
    throw new Error("invalid number of shares")
  }
  let xs = Array(share_list.length)
  let ys = Array(share_list.length)
  // xs := make([]*ristretto.Scalar, len(shares))
  // ys := make([]*ristretto.Scalar, len(shares))

  for (let i = 0; i < share_list.length; i++) {
    ys[i] = p256.scalar().fromBN(share_list[i].V)
    xs[i] = p256.scalar().fromNumber(share_list[i].I + 1, 'be')
  }

  return interpolate(xs, ys)
}

// Lagrange interpolation
function interpolate (xs, ys) {
  let result = p256.scalar().fromNumber(0, 'be')
  let num
  let den
  let one = p256.scalar().fromNumber(1, 'be')
  for (let i = 0; i < xs.length; i++) {
    num = p256.scalar().fromNumber(1, 'be')
    den = p256.scalar().fromNumber(1, 'be')
    for (let j = 0; j < xs.length; j++) {
      if (i === j) {
        continue
      }
      num = num.mul(xs[j])
      den = den.mul(xs[j].sub(xs[i]))
    }
    result = result.add(ys[i].mul(num.mul(den.invert(p256.n)))).mod(p256.n)
  }
  return result
}


function CombineLambda (share_list, t) {
  if (share_list.length < t + 1) {
    throw new Error("invalid number of shares")
  }
  let xs = Array(share_list.length)

  for (let i = 0; i < share_list.length; i++) {
    xs[i] = p256.scalar().fromNumber(share_list[i].result.i + 1, 'be')
  }

  return interpolateLambda(xs)
}


function interpolateLambda (xs) {
  let result = Array(xs.length)
  let num
  let den
  let one = p256.scalar().fromNumber(1, 'be')
  for (let i = 0; i < xs.length; i++) {
    num = p256.scalar().fromNumber(1, 'be')
    den = p256.scalar().fromNumber(1, 'be')
    for (let j = 0; j < xs.length; j++) {
      if (i === j) {
        continue
      }
      num = num.mul(xs[j])
      den = den.mul(xs[j].sub(xs[i]))
    }
    result[i] = num.mul(den.invert(p256.n))
    // result = result.add(ys[i].mul(num.mul(den.invert(p256.n)))).mod(p256.n)
  }
  return result
}

function tdh2Encrypt_fromGO (pub, msg, label) {
  if (pub.Group !== groupName)
    throw Error('invalid group')
  let g_bar = p256.decodePoint(Buffer.from(pub.G_bar, 'base64'))
  let h = p256.decodePoint(Buffer.from(pub.H, 'base64'))

  const r = p256.randomScalar(rnd)
  const s = p256.randomScalar(rnd)

  const c = xor(hash1(h.mul(r)), msg)

  const u = p256.g.mul(r)
  const w = p256.g.mul(s)
  const uBar = g_bar.mul(r)
  const wBar = g_bar.mul(s)

  const e = hash2(c, label, u, w, uBar, wBar)
  const f = s.add(r.mul(e).mod(p256.n)).mod(p256.n)

  /*console.log("c-------", c.toString('base64'))
  console.log(" ")
  console.log("label-------", label.toString('base64'))
  console.log(" ")
  console.log("u-------", p256.encodePoint(u, false).toString('base64'))
  console.log(" ")
  console.log("w-------", p256.encodePoint(w, false).toString('base64'))
  console.log(" ")
  console.log("uBar-------", p256.encodePoint(uBar, false).toString('base64'))
  console.log(" ")
  console.log("wBar-------", p256.encodePoint(wBar, false).toString('base64'))
  console.log(" ")
  console.log("e-------", p256.encodeScalar(e).toString('base64'))
  console.log(" ")*/
  return JSON.stringify({
    Group: groupName,
    C: c.toString('base64'),
    Label: label.toString('base64'),
    U: p256.encodePoint(u, false).toString('base64'),
    U_bar: p256.encodePoint(uBar, false).toString('base64'),
    E: p256.encodeScalar(e).toString('base64'),
    F: p256.encodeScalar(f).toString('base64'),
  })
}

// Input the pub_key generate by JS
function tdh2EncryptInner (pub, msg, label) {
  if (pub.Group !== groupName)
    throw Error('invalid group')
  // g_bar = p256.decodePoint(Buffer.from(pub.G_bar, 'base64'))
  // h = p256.decodePoint(Buffer.from(pub.H, 'base64'))

  const r = p256.randomScalar(rnd)
  const s = p256.randomScalar(rnd)


  const c = xor(hash1(pub.h.mul(r)), msg)
  // const c = hash1(pub.h.mul(r))

  const u = pub.g.mul(r)
  const w = pub.g.mul(s)
  const uBar = pub.g_bar.mul(r)
  const wBar = pub.g_bar.mul(s)

  const e = hash2(c, label, u, w, uBar, wBar)
  const f = s.add(r.mul(e).mod(p256.n)).mod(p256.n)

  return {
    Group: groupName,
    C: c,
    Label: label,
    U: u,
    U_bar: uBar,
    E: e,
    F: f,
  }
}



// check e = H3(g_bar, u_bar, w_bar)
function tdh2Check (ct, pub) {
  // check generate w, w_bar
  // w = g*f - u*e
  let w = p256.g.mul(ct.F)
  w = w.sub(ct.U.mul(ct.E))
  // w_bar = g_bar ^ f - u_bar ^ e
  let w_bar = pub.g_bar.mul(ct.F)
  w_bar = w_bar.sub(ct.U_bar.mul(ct.E))
  // hash2(c, L, u, w, u_bar, w_bar)
  let e_eval = hash2(ct.C, ct.Label, ct.U, w, ct.U_bar, w_bar)
  // check e = hash2(.) ?
  return e_eval.toString() === ct.E.toString()

}

// input c:{c, L, u , u_bar, e, f}
function tdh2Decryption (ct, sk) {
  let check_result = tdh2Check(ct, sk.Pub)
  if (check_result === false) {
    throw Error('verify e != hash2')
  }
  // sample random s_i
  let s_i = p256.randomScalar(rnd)
  let u_i = ct.U.mul(sk.xi)
  let u_i_hat = ct.U.mul(s_i)
  let h_i_hat = sk.Pub.g.mul(s_i)
  let e_i = hash4(u_i, u_i_hat, h_i_hat)
  let f_i = s_i.add(sk.xi.mul(e_i).mod(p256.n)).mod(p256.n)
  return {
    result: new Decrypt_result(sk.i, u_i, e_i, f_i)
  }
}

function combineShare (vk, ct, dt_list, t) {
  let check_result = tdh2Check(ct, vk.Pub)
  if (check_result === false) {
    throw Error('verify e != hash2')
  }
  let lambda_list = CombineLambda(dt_list, t)
  let result = p256.point()

  for (let i = 0; i < lambda_list.length; i++) {
    result = result.add(dt_list[i].result.u_i.mul(lambda_list[i]))
  }
  return xor(hash1(result), ct.C)
}

function verifyShare (ct, vk, dt) {
  let check_result = tdh2Check(ct, vk.Pub)
  if (check_result === false) {
    throw Error('verify e != hash2')
  }
  // u_i_hat = u ^ f_i / u_i ^ e_i
  let u_i_hat = ct.U.mul(dt.result.f_i)
  u_i_hat = u_i_hat.sub(dt.result.u_i.mul(dt.result.e_i))
  // h_i_hat = g ^ f_i / h_i ^ e_i
  let h_i_hat = vk.Pub.g.mul(dt.result.f_i)
  h_i_hat = h_i_hat.sub(vk.tuple[dt.result.i].mul(dt.result.e_i))

  // check e_i = hash4(.) ?
  let e_i_eval = hash4(dt.result.u_i, u_i_hat, h_i_hat)
  return dt.result.e_i.toString() === e_i_eval.toString()
}


function concatenate (points) {
  let out = groupName
  for (let i = 0; i < points.length; i++) {
    out += "," + toHexString(p256.encodePoint(points[i], false))
  }

  return Buffer.from(out)
}

function hash1 (point) {
  return sm3hash(Buffer.concat([
    Buffer.from("tdh2hash1"),
    concatenate([point])
  ]))
}

function hash2 (msg, label, p1, p2, p3, p4) {
  if (msg.length !== tdh2InputSize)
    throw new Error('message has incorrect length')

  if (label.length !== tdh2InputSize)
    throw new Error('label has incorrect length')

  input = Buffer.concat([
    Buffer.from("tdh2hash2"),
    msg,
    label,
    concatenate([p1, p2, p3, p4])
  ])

  //console.log("Before sm3---", input.toString('base64'))
  const h = sm3hash(input)
  //console.log("h in hash2---", h.toString('base64'))
  return p256.decodeScalar(h)
}

function hash4 (p1, p2, p3) {

  input = Buffer.concat([
    Buffer.from("tdh2hash4"),
    concatenate([p1, p2, p3])
  ])

  //console.log("input---", input.toString('base64'))
  const h = sm3hash(input)
  //console.log("h in hash4---", h.toString('base64'))

  return p256.decodeScalar(h)
}

function xor (a, b) {
  buffer_a = Buffer.from(a)
  //console.log(a.length)
  // console.log(buffer_a.length)
  //console.log(b.length)
  if (buffer_a.length !== b.length)
    throw new Error('buffers with different lengths')

  var out = Buffer.alloc(a.length)
  for (var i = 0; i < a.length; i++) {
    out[i] = a[i] ^ b[i]
  }

  return out
}


function keyToAsciiArray (key) {
  const asciiArray = []
  for (let i = 0; i < key.length; i++) {
    asciiArray.push(key.charCodeAt(i))
  }
  return asciiArray
}


function generateRandomKey (length) {
  const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
  let randomKey = ""
  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * charset.length)
    randomKey += charset.charAt(randomIndex)
  }
  return randomKey
}

function encrypt (pub, msg) {
  /*const ciph = new Cipher('AES-256-GCM');
  const blockSize = 16;
  const key =  rnd.randomBytes(tdh2InputSize);
  const nonce = rnd.randomBytes(12);

  ciph.init(key, nonce);
  if (msg.length > ((2**32)-2)*blockSize)
    throw new Error('message too long');
  const ctxt = Buffer.concat([
    ciph.update(msg),
    ciph.final(),
    ciph.getAuthTag()
  ]);

  console.log("This is the key---", key.toString('base64'))*/
  const blockSize = 16
  const key_tdh2 = generateRandomKey(32)
  const key_tdh2_byte = Buffer.from(key_tdh2)
  //console.log(key_tdh2)
  //console.log(Buffer.from(key_tdh2))
  const key_SM4 = key_tdh2.substring(0, 16)
  const real_key_SM4 = keyToAsciiArray(key_SM4)

  const nonce = crypto.randomBytes(12)
  //const iv = rnd.randomBytes(16);
  //const iv = [0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30]

  if (msg.length > ((2 ** 32) - 2) * blockSize)
    throw new Error('message too long')

  const ctxt = sm4.encrypt(msg, real_key_SM4)

  console.log("SM4 key---", key_SM4.toString('base64'))

  const tdh2Ctxt = tdh2Encrypt_fromGO(pub, key_tdh2_byte, Buffer.alloc(tdh2InputSize))

  const result = {
    TDH2Ctxt: Buffer.from(tdh2Ctxt).toString('base64'),
    SymCtxt: Buffer.from(ctxt, 'hex').toString('base64'),
    Nonce: nonce.toString('base64'),
  }

  return {
    jsonString: JSON.stringify(result),
    tdh2Ctxt: tdh2Ctxt,
    ctxt: ctxt,
  }

}

function verify_share (cipher, pk, share_i) {
  //parse corresponding segments of ciphertext
  const TDH2CtxtBase64 = cipher.TDH2Ctxt
  const TDH2CtxtBuffer = Buffer.from(TDH2CtxtBase64, 'base64')
  const TDH2CtxtObject = JSON.parse(TDH2CtxtBuffer.toString('utf8'))
  const cipher_group = TDH2CtxtObject.Group

  //The first comparision
  if (pk.Group !== cipher_group) {
    throw Error('incorrect ciphertext group')
  }
  //The second comparision
  if (pk.Group !== share_i.Group) {
    throw Error('incorrect ciphertext group')
  }
  //The third comparision
  let check_result = verify_Check(TDH2CtxtObject, pk)
  if (check_result === false) {
    throw Error('verify e != hash2')
  }

  U = p256.decodePoint(Buffer.from(TDH2CtxtObject.U, 'base64'))
  E_i = p256.decodeScalar(Buffer.from(share_i.E_i, 'base64'))
  F_i = p256.decodeScalar(Buffer.from(share_i.F_i, 'base64'))
  U_i = p256.decodePoint(Buffer.from(share_i.U_i, 'base64'))
  index = share_i.Index
  //u_i_hat = u ^ f_i / u_i ^ e_i
  //let u_i_hat = U.mul(F_i)
  let u_i_hat = (U.mul(F_i)).sub(U_i.mul(E_i))

  const pk_hArray = pk.HArray
  const pk_i_hArray = p256.decodePoint(Buffer.from(pk_hArray[index], 'base64'))

  // h_i_hat = g ^ f_i / h_i ^ e_i
  let h_i_hat = p256.g.mul(F_i)
  h_i_hat = h_i_hat.sub(pk_i_hArray.mul(E_i))

  /*console.log("U_i---", share_i.U_i)
  console.log("U_i length ---", share_i.U_i.length)
  console.log("E_i---", share_i.E_i)
  console.log("E_i length ---", share_i.E_i.length)
  console.log("F_i---", share_i.F_i)
  console.log("")
  console.log("u_i_hat---", p256.encodePoint(u_i_hat).toString('base64'))
  console.log("u_i_hat length---", (p256.encodePoint(u_i_hat).toString('base64')).length)
  console.log("")
  console.log("h_i_hat---", p256.encodePoint(h_i_hat).toString('base64'))
  console.log("")*/

  // check e_i = hash4(.) ?
  let e_i_eval = hash4(U_i, u_i_hat, h_i_hat)
  //console.log(p256.encodeScalar(E_i).toString('base64'))
  //console.log(p256.encodeScalar(e_i_eval).toString('base64'))
  return E_i.toString() === e_i_eval.toString()

}

// check e = H3(g_bar, u_bar, w_bar)
function verify_Check (ct, pub) {
  // check generate w, w_bar
  // w = g*f - u*e
  F = p256.decodeScalar(Buffer.from(ct.F, 'base64'))
  E = p256.decodeScalar(Buffer.from(ct.E, 'base64'))
  U = p256.decodePoint(Buffer.from(ct.U, 'base64'))
  U_bar = p256.decodePoint(Buffer.from(ct.U_bar, 'base64'))
  g_bar = p256.decodePoint(Buffer.from(pub.G_bar, 'base64'))

  C = Buffer.from(ct.C, 'base64')
  Label = Buffer.from(ct.Label, 'base64')

  let w = p256.g.mul(F)
  w = w.sub(U.mul(E))
  // w_bar = g_bar ^ f - u_bar ^ e
  let w_bar = g_bar.mul(F)
  w_bar = w_bar.sub(U_bar.mul(E))
  // hash2(c, L, u, w, u_bar, w_bar)
  let e_eval = hash2(C, Label, U, w, U_bar, w_bar)
  // check e = hash2(.) ?
  return e_eval.toString() === E.toString()
}

function combine_Share (pk, cipher, shares, t) {
  const TDH2CtxtBase64 = cipher.TDH2Ctxt
  const TDH2CtxtBuffer = Buffer.from(TDH2CtxtBase64, 'base64')
  const TDH2CtxtObject = JSON.parse(TDH2CtxtBuffer.toString('utf8'))
  C = Buffer.from(TDH2CtxtObject.C, 'base64')

  let check_result = verify_Check(TDH2CtxtObject, pk)
  if (check_result === false) {
    throw Error('verify e != hash2')
  }
  let lambda_list = Combine_Lambda(shares, t)
  let result = p256.point()

  for (let i = 0; i < lambda_list.length; i++) {
    U_i = p256.decodePoint(Buffer.from(shares[i].U_i, 'base64'))
    result = result.add(U_i.mul(lambda_list[i]))
  }
  return xor(hash1(result), C)
}

function Combine_Lambda (share_list, t) {
  if (share_list.length < t + 1) {
    throw new Error("invalid number of shares")
  }
  let xs = Array(share_list.length)

  for (let i = 0; i < share_list.length; i++) {
    xs[i] = p256.scalar().fromNumber(share_list[i].Index + 1, 'be')
  }

  return interpolateLambda(xs)
}

function decrypt_SM4 (key_TDH2, cipher) {
  const data = cipher
  //console.log(key_TDH2.toString())
  //const iv = [0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30]
  const key_SM4 = (key_TDH2.toString()).substring(0, 16)
  const real_key_SM4 = keyToAsciiArray(key_SM4)
  console.log("This is the SM4 key---", key_SM4)
  // 从Base64字符串解码TDH2Ctxt、SymCtxt和Nonce
  //const ctxt = Buffer.from(data.SymCtxt, 'base64');
  C = Buffer.from(data.SymCtxt, 'base64')
  const decmsg = sm4.decrypt(C, real_key_SM4)

  return decmsg // 解密，cbc 模式
}


function decrypt_AESGCM (key, encryptedData) {
  // 解析JSON字符串
  const data = encryptedData

  // 从Base64字符串解码TDH2Ctxt、SymCtxt和Nonce
  const tdh2Ctxt = Buffer.from(data.TDH2Ctxt, 'base64')
  const ctxt = Buffer.from(data.SymCtxt, 'base64')
  const nonce = Buffer.from(data.Nonce, 'base64')

  // 使用相同的AES-GCM参数初始化解密器
  const decipher = new Cipher('AES-256-GCM')
  decipher.init(key, nonce)

  // 分离密文部分和认证标签部分
  const ciphertext = ctxt.slice(0, ctxt.length - 16) // 前面的部分是密文
  //const authTag = ctxt.slice(ctxt.length - 16); // 后面的部分是认证标签


  // 解密密文部分
  const decryptedMsg = Buffer.concat([
    decipher.update(ciphertext), // 解密密文部分
    decipher.final() // 完成解密
    //decipher.setAuthTag()
  ])

  // 返回解密后的消息
  return decryptedMsg // 假设消息是UTF-8编码的
}


//hash
//buffer.from  ->  string (base 64) -> sm3 -> string -> buffer.from ('hex')



module.exports = { decrypt_SM4, decrypt_AESGCM, combine_Share, verify_share, encrypt, GenerateKeys, newPoly, ployShare, Combine, tdh2EncryptInner, tdh2Decryption, verifyShare, combineShare, p256, sm3hash }