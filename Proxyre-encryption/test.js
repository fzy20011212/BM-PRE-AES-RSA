const PRE = require('./pre.js');
 const prompt = require('prompt-sync')();
 const fs = require('fs');

PRE.init({g: "The generator for G1", h:"The generator for G2", returnHex:false}).then(params =>{

    let decryptedKey = '76553b0df76745c77df3c390ff3ba5fe';
    const plain = PRE.randomGen(); //generate random element
    const plainRandom = decryptedKey +plain.substring(32);


    //const userinput = prompt("userinput：");
    //const plain = PRE.strToHex(userinput);
    //console.log("hex string:",plain);

    const A = PRE.keyGenInG1(params,{returnHex: true});
    const B = PRE.keyGenInG2(params,{returnHex: true});
    //generate key pairs of A and B

    const encrypted = PRE.enc(plainRandom, A.pk, params, {returnHex: true});
    const decrypted = PRE.dec(encrypted, A.sk, params);

    console.log(plainRandom === decrypted);
    //encryption and decryption

    const reKey = PRE.rekeyGen(A.sk, B.pk, {returnHex:true});

    const rekey_json = JSON.stringify(reKey);
    const rekeypath = './test rekey.json';
    //generate re-encryption key
    fs.writeFile(rekeypath, rekey_json,(err) =>{
        if(err){
            console.error('出错啦：',err);
            return;
        }
        console.log('rekey已成功写入');
    })

    fs.readFile(rekeypath, 'utf8', (err, data) => {
        if(err){
            console.log('出错啦：', err);
            return;
        }
        const loaded_rekey = JSON.parse(data);
        const reEncrypted = PRE.reEnc(encrypted, loaded_rekey, {returnHex: true});
        console.log('reEncrypted:', reEncrypted);
        const reDecrypted = PRE.reDec(reEncrypted, B.sk);
        console.log(reDecrypted === plainRandom);
    })


   /*
    console.log(plainRandom === reDecrypted)
    //Re-Encryption and Re-Decryption

    let data = reDecrypted.substring(0, reDecrypted.length - 32)

    const crypto = require('crypto');
    const msg = "1111";
    const hash = crypto.createHash('sha256');
    hash.update(msg);
    const msgHash = hash.digest('hex');

    console.log("decryptedKey\n", decryptedKey);
    console.log("plain\n", plain);
    console.log("plainRandom\n", plainRandom);
    console.log("A's key pair\n", A);
    console.log("B's key pair\n", B);
    console.log("encrypted\n", encrypted);
    console.log("decrypted\n", decrypted);
    console.log("reKey\n", reKey);
    console.log("reEncrypted\n", reEncrypted);
    console.log("reDecrypted\n", reDecrypted);
    console.log("data\n", data);
    console.log(data === decryptedKey)



    */



}).catch(err => {
    console.log(err)
});