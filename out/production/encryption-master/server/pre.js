const mcl = require('mcl-wasm');
const {deserializeHexStrToG2} = require("mcl-wasm");

class PRE{

    /**
     * setup by g,h and curve to create G1 & G2, return the generators
     * @param g {string} the generator of G1, G1 的生成器，可以是字符串或十六进制字符串（通过 PRE 转储）
     * @param h {string} the generator of G2, G2 的生成器，可以是字符串或十六进制字符串（通过 PRE 转储）
     * @param curve {number} the curve type
     * @param fromHex {boolean} whether return g and h in hex string or object
     * @param returnHex {boolean} whether return g and h in hex string
     * @returns {Promise<{g: G1, h: G2}|{g, h}>}
     */

    static async init({g, h, curve = mcl.BLS12_381, fromHex = false, returnHex = false}){
        await mcl.init(curve);
        const gPoint = fromHex ? mcl.deserializeHexStrToG1(g) : mcl.hashAndMapToG1(g);
        const hPoint = fromHex ? mcl.deserializeHexStrToG2(h) : mcl.hashAndMapToG2(h);
        if (returnHex){
            return {g:PRE.dump(gPoint), h:PRE.dump(hPoint)}
        }
        return{g: gPoint, h: hPoint}

    }
    // init: 初始化ECC，用于设置 G1 和 G2 群的生成器，并根据需要将它们转换为十六进制字符串或其对象表示
    // 将十六进制字符串g/h 解析为G1/G2 群的一个点，并将字符串g/h 散列并映射到G1/G2群中
    // 将返回的g和h转换为十六进制字符串

    /**
     * generate the key pair for the delegator
     * @param g {string|mcl.G1} the hex string or G1 of g
     * @param returnHex whether return key pair in hex string or object
     * @returns {{sk: (*|Fr), pk: Fr}}
     */

    static keyGenInG1({g},{returnHex = false} = {}){
        const sk = PRE.randomInFr();
        const pk = PRE.getPkFromG1(sk, g, {returnHex: returnHex});
        return{
            sk: returnHex ? PRE.dump(sk) : sk,
            pk: pk
        }
    }
    // keyGenInG1: 用于生成基于G1椭圆曲线密码学的密钥对
    // g是G1上的点，作为生成元
    // 生成随机数sk，作为私钥，使用sk和g生成公钥pk，最后返回sk和pk

    /**
     * generate the key pair for the delegator
     * @param h {string|mcl.G2} the hex string or G2 of h
     * @param returnHex whether return key pair in hex string of object
     * @returns {{sk: (*|Fr), pk: Fr}}
     */

    static keyGenInG2({h},{returnHex = false} = {}){
        const sk = PRE.randomInFr();
        const pk = PRE.getPkFromG2(sk, h, {returnHex: returnHex});
        return{
            sk: returnHex ? PRE.dump(sk) : sk,
            pk: pk
        }
    }
    // keyGenInG2: 用于生成基于G2的椭圆曲线密码学的密钥对


    /**
     * get the delegator's pk from sk
     * @param ska  {string|mcl.Fr} the hex string or Fr of ska
     * @param g {string|mcl.G1} the hex string or G1 of g
     * @param returnHex whether return pk in hex string or object
     * @returns {string|mcl.G1}
     */

    static getPkFromG1(ska,g,{returnHex = false} = {}){
        const point = typeof(ska) === "string" ? mcl.deserializeHexStrToFr(ska) : ska;
        const gPoint = typeof(g) === "string" ? mcl.deserializeHexStrToG1(g) : g;
        const pka = mcl.mul(gPoint, point);
        return returnHex ? PRE.dump(pka) : pka;

    }
    // getPkFromG1: 计算ska和g的乘积并返回结果pka

    /**
     * get the delegator's pk from sk
     * @param skb {string|mcl.Fr} the hex string or Fr of skb
     * @param h {string|mcl.G2} the hex string or G2 of h
     * @param returnHex whether return pk in hex string or object
     * @returns {string|mcl.G2}
     */

    static getPkFromG2(skb,h,{returnHex = false} = {}){
        const point = typeof(skb) === "string" ? mcl.deserializeHexStrToFr(skb) : skb;
        const hPoint = typeof (h) === "string" ? mcl.deserializeHexStrToG2(h) : h;
        const pka = mcl.mul(hPoint, point);
        return returnHex ? PRE.dump(pka) : pka;

    }
    // getPkFromG2: 计算skb和h的乘积并返回结果pka

    /**
     * encryption from delegator's pk
     * @param plain {string} must be valid hex string form from PRE.dump
     * @param pk {string|mcl.G1} the hex string or G1 of pk
     * @param g {string|mcl.G1} the hex string or G1 of g
     * @param h {string|mcl.G2} the hex string or G2 of h
     * @param returnHex whether return encrypted in hex stirng or object
     * @returns {array} [gak,mzk]
     */

    static enc(plain, pk, {g,h}, {returnHex = false} = {}){
        const gPoint = typeof (g) === "string" ? mcl.deserializeHexStrToG1(g) : g;
        const hPoint = typeof (h) === "string" ? mcl.deserializeHexStrToG2(h) : h;
        const  pkPoint = typeof(pk) === "string" ? mcl.deserializeHexStrToG1(pk) : pk;
        const m = mcl.deserializeHexStrToFr(plain);
        const k = PRE.randomInFr();

        const gak = mcl.mul(pkPoint, k);
        const z = mcl.pairing(gPoint, hPoint);

        const mzk = mcl.add(m, mcl.hashToFr(mcl.pow(z, k).serialize()));
        return returnHex ? [PRE.dump(gak),PRE.dump(mzk)] : [gak, mzk]

    }
    // encryption
    // 检查g,h,pk是否字符串
    // 将明文plain从十六进制字符串转换为有限域Fr中的元素
    // 生成随机数k，将其转换为Fr中的元素
    // 计算gak，即将公钥pkPoint与私钥k相乘
    // 计算配对值z，即将点gPoint和hPoint进行配对，将两个点映射到一个大的有限域中
    // 计算密文mzk，即将 明文m 与 通过将 配对值z的k次幂 哈希到有限域Fr中 的元素 相加
    // 返回gzk，mzk

    /**
     * decryption from delegator's sk
     * @param encrypted {array} the encrypted part, either hex string or object
     * @param sk {string|mcl.Fr} the hex string or Fr of sk
     * @param h {string|mcl.G2} the hex string or G2 of h
     * @returns {string} the original hex string
     */

    static dec(encrypted, sk, {h}){
        const [gak, mzk] = encrypted;
        const gakPoint = typeof(gak) === "string" ? mcl.deserializeHexStrToG1(gak) : gak;
        const mzkPoint = typeof(mzk) === "string" ? mcl.deserializeHexStrToFr(mzk) : mzk;
        const hPoint = typeof(h) === "string" ? mcl.deserializeHexStrToG2(h) : h;
        const skPoint = typeof(sk) === "string" ? mcl.deserializeHexStrToFr(sk) : sk;
        const eah = mcl.pairing(gakPoint, hPoint);
        const eahInvSk = mcl.pow(eah, mcl.inv(skPoint));
        const decrypted = mcl.sub(mzkPoint, mcl.hashToFr(eahInvSk.serialize()));
        return PRE.dump(decrypted)

    }
    // decryption
    // 将encrypted解构为[gak,mzk]
    // 将gak，mzk，h，sk转换为G1，Fr，G2，Fr中的元素
    // 计算eah，即将点gakPoint与hPoint进行配对
    // 计算eahInvSk，即将ska的倒数与eah相乘
    // 计算解密后的消息decrypted， 即将密文mzkPoint与 通过将eahInSk的哈希值 相减 得到的结果结合
    // 返回decrypted


    /**
     * generate reKey from delegator's sk and delegate's pk
     * @param ska {string|mcl.Fr} the hex string or Fr of ska
     * @param pkb {string|mcl.G2} the hex string or G2 of pkb
     * @param returnHex whether return reKey in hex string or object
     * @returns {string|mcl.G2}
     */

    static rekeyGen(ska, pkb, {returnHex = false} = {}){
        const  skaPoint = typeof(ska) === "string" ? mcl.deserializeHexStrToFr(ska) : ska;
        const  pkbPoint = typeof(pkb) === "string" ? mcl.deserializeHexStrToG2(pkb) : pkb;
        const  reKey = mcl.mul(pkbPoint, mcl.inv(skaPoint));
        return returnHex ? PRE.dump(reKey) : reKey
    }
    // re-key generation
    // 用ska和pkb生成reKey
    // reKey是将pkPoint与skaPoint的倒数相乘

    /**
     * re-encryption from encrypted and reKey
     * @param encrypted {array} the encrypted part
     * @param reKey the hex string or G2 of pkb
     * @param returnHex whether return reEncrypted in hex string or object
     * @returns {array}
     */

    static reEnc(encrypted, reKey, {returnHex = false} = {}){
        let [gak, mzk] = encrypted;
        const gakPoint = typeof(gak) === "string" ? mcl.deserializeHexStrToG1(gak) : gak;
        const reKeyPoint = typeof(reKey) === "string" ? mcl.deserializeHexStrToG2(reKey) : reKey;
        let Zbk = mcl.pairing(gakPoint, reKeyPoint);
        if (returnHex)
            Zbk = PRE.dump(Zbk);
        if (typeof(mzk) === "string" && !returnHex )
            mzk = mcl.deserializeHexStrToFr(mzk);
        if (typeof(mzk) !== "string" && returnHex)
            mzk = PRE.dump(mzk);

        return [Zbk, mzk]
    }
    // re-Encryption
    // 配对gakPoint和reKeyPoint，并将结果赋值给zbk
    // 返回[zbk,mzk]的数组

    /**
     * re-decryption from re-encrypted and delegate's sk
     * @param reEncrypted {array} the re-encrypted part
     * @param sk {String|mcl.Fr} the hex string or Fr of sk
     * @returns {string} the original hex string
     */

    static reDec(reEncrypted, sk){
        let [Zbk, mzk] = reEncrypted;
        const skPoint = typeof(sk) === "string" ? mcl.deserializeHexStrToFr(sk) : sk;
        const ZbkPoint = typeof(Zbk) === "string" ? mcl.deserializeHexStrToGT(Zbk) : Zbk;
        const  mzkPoint = typeof(mzk) === "string" ? mcl.deserializeHexStrToFr(mzk) : mzk;

        const ZbkInvB = mcl.pow(ZbkPoint, mcl.inv(skPoint));
        const reDecrypted = mcl.sub(mzkPoint, mcl.hashToFr(ZbkInvB.serialize()));
        return PRE.dump(reDecrypted)
    }
    // re-Decryption
    // 计算zbk的倒数的平方-> ZbkInvB
    // 使用mzkPoint减去ZbkInvB的哈希转换得到Fe类型的点-> reDecrypted


    /**
     * generate random hex string in Fr, normally used to generate symmetric key
     * @returns {string}
     */
    static randomGen(){
        return PRE.dump(PRE.randomInFr());
    }

    /**
     * generate random element in Fr
     * @returns {mcl.Fr}
     */
    static randomInFr(){
        const p = new mcl.Fr();
        p.setByCSPRNG();
        return p
    }

    /**
     * dump point/element to hex string
     * @param obj
     * @returns {string}
     */
    static dump(obj){
        return obj.serializeToHexStr()
    }
    // 将点或元素转换为十六进制字符串

    static strToHex(inputString){
        let hexoutput = '';
        for (let i = 0; i<inputString.length; i++){
            const hex = inputString.charCodeAt(i).toString(16);
            hexoutput += hex;
        }
        return hexoutput;
    }

    }
    module.exports = PRE;