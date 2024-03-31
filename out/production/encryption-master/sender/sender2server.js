const PRE = require('./pre.js');
const fs = require('fs');
const readline = require('readline');
const mcl = require('mcl-wasm');
const mcl1 = require('mcl')
const prompt = require('prompt-sync')();

PRE.init({g: "The generator for G1", h:"The generator for G2", returnHex:false}).then(params => {

    //下面是对加密的AES密钥 encKey 的读取操作，方便进行PRE的第一次加密
    //let encKey = '426e0a4cf1328df9b7147f97362e8b993e4cdc8a471a1628e97744255571d6c3247c68301ceadbb378a119f4d06224ad740631e26fce3d9b8a34edf4e435c4dfaeab91c4e2fae451127ec7390b5590ce52167a589866bde593800224150d7c27fbdec4160343d7b229f81fe08eeb4e01d2f68a24f817f9b552b49c15070c1df7';
    fs.readFile('D:\\\\Fan\\\\A bishe\\\\project\\\\enckey\\\\enckey.txt', 'utf8', (err, encKey) => {
        if (err) {
            console.error('读取文件时出错：', err);
            return;
        }

        // console.log("enckey:", encKey);

        // 下面是把encKey分段并加上随机明文
        const plain = PRE.randomGen(); //generate random element
        //const plainRandom = encKey + plain.substring(32);
        let encKey1 = encKey.slice(0, 32) + plain.substring(32); // 第1段，从第0位开始，取64位
        let encKey2 = encKey.slice(32, 64)+ plain.substring(32); // 第2段，从第64位开始，取64位
        let encKey3 = encKey.slice(64, 96)+ plain.substring(32); // 第3段，从第128位开始，取64位
        let encKey4 = encKey.slice(96, 128)+ plain.substring(32); // 第4段，从第192位开始，取64位
        let encKey5 = encKey.slice(128, 160)+ plain.substring(32);; // 第1段，从第0位开始，取64位
        let encKey6 = encKey.slice(160, 192)+ plain.substring(32);; // 第2段，从第64位开始，取64位
        let encKey7 = encKey.slice(192, 224)+ plain.substring(32);; // 第3段，从第128位开始，取64位
        let encKey8 = encKey.slice(224, 256)+ plain.substring(32);; // 第4段，从第192位开始，取64位

        // 注释掉的部分是第一次生成A和B的公私钥对，存储到PREKey.A_Key.txt和B_Key.txt中

        /*
            //const userinput = prompt("userinput：");
            //const plain = PRE.strToHex(userinput);
            //console.log("hex string:",plain);

            const A = PRE.keyGenInG1(params, {returnHex: true});
            const B = PRE.keyGenInG2(params, {returnHex: true});
            //generate key pairs of A and B
            // console.log("A's key pair\n", A);
            // console.log("B's key pair\n", B);
            const AprivateKeyHex = A.sk;
            const ApublicKeyHex = A.pk;
            const BprivateKeyHex = B.sk;
            const BpublicKeyHex = B.pk;

            // 将密钥转换为字符串
            const AprivateKeyString = `Private Key: ${AprivateKeyHex}`;
            const ApublicKeyString = `Public Key: ${ApublicKeyHex}`;
            const BprivateKeyString = `Private Key: ${BprivateKeyHex}`;
            const BpublicKeyString = `Public Key: ${BpublicKeyHex}`;
            */

        const filePathA = 'D:\\\\Fan\\\\A bishe\\\\project\\\\PREKey\\\\A_key.txt';
        /*
            fs.writeFile(filePathA, `${AprivateKeyString}\n${ApublicKeyString}`, (err) => {
                if (err) {
                    console.error('写入文件时出错：', err);
                    return;
                }
                console.log('密钥已成功存储到 A_key.txt 文件中。');
            });
            */

        const filePathB = 'D:\\\\Fan\\\\A bishe\\\\project\\\\PREKey\\\\B_key.txt';
        /*

        fs.writeFile(filePathB, `${BprivateKeyString}\n${BpublicKeyString}`, (err) => {
            if (err) {
                console.error('写入文件时出错：', err);
                return;
            }
            console.log('密钥已成功存储到 B_key.txt 文件中。');
        });

     */
        // 定义全局变量
        //let A_privateKey = null;
        // let A_publicKeyHex = null;
        //let B_privateKey = null;
        // let B_publicKey = null;
        /*
            fs.readFile(filePathB, 'utf8',(err, data) =>{
                if(err){
                    console.error("error:",err);
                }
                const [BprivateKeyString, BpublicKeyString] = data.trim().split('\n');
                const BprivateKeyHex = BprivateKeyString.split(':')[1].trim();
                const BpublicKeyHex = BpublicKeyString.split(':')[1].trim();
                B_privateKey = BprivateKeyHex;
                B_publicKey = BpublicKeyHex;
                console.log(BpublicKeyHex === B_publicKey);
                console.log(BprivateKeyHex === B_privateKey);

            })

         */

        // 下面是从文件中读取A的私钥和B的公钥

        fs.readFile(filePathA, 'utf8', (err, data) => {
            if (err) {
                console.error('读取文件时出错：', err);
                return;
            }
            // 将文件中的内容分割成私钥和公钥字符串
            const [AprivateKeyString, ApublicKeyString] = data.trim().split('\n');
            // 提取私钥和公钥的十六进制表示
            const AprivateKeyHex = AprivateKeyString.split(':')[1].trim();
            const ApublicKeyHex = ApublicKeyString.split(':')[1].trim();

            fs.readFile(filePathB, 'utf8',(err, data) =>{
                if(err){
                    console.error("error:",err);
                }
                const [BprivateKeyString, BpublicKeyString] = data.trim().split('\n');
                const BprivateKeyHex = BprivateKeyString.split(':')[1].trim();
                const BpublicKeyHex = BpublicKeyString.split(':')[1].trim();


                // 下面是用A.pk 计算enc_c1
                const encrypted1 = PRE.enc(encKey1, ApublicKeyHex, params, {returnHex: true});
                //console.log("encrypt1:",encrypted1);
                const encrypted2 = PRE.enc(encKey2, ApublicKeyHex, params, {returnHex: true});
                 //console.log("encrypt2:",encrypted2);
                const encrypted3 = PRE.enc(encKey3, ApublicKeyHex, params, {returnHex: true});
                //console.log("encrypt3:",encrypted3);
                const encrypted4 = PRE.enc(encKey4, ApublicKeyHex, params, {returnHex: true});
               // console.log("encrypt4:",encrypted4);
                const encrypted5 = PRE.enc(encKey5, ApublicKeyHex, params, {returnHex: true});
                //console.log("encrypt5:",encrypted5);
                const encrypted6 = PRE.enc(encKey6, ApublicKeyHex, params, {returnHex: true});
                //console.log("encrypt6:",encrypted6);
                const encrypted7 = PRE.enc(encKey7, ApublicKeyHex, params, {returnHex: true});
                //console.log("encrypt7:",encrypted7);
                const encrypted8 = PRE.enc(encKey8, ApublicKeyHex, params, {returnHex: true});
               // console.log("encrypt8:",encrypted8);

                const enc_c1 = [...encrypted1, ...encrypted2, ...encrypted3, ...encrypted4, ...encrypted5, ...encrypted6, ...encrypted7, ...encrypted8];
                console.log("enc_c1:",enc_c1);


                // 下面是enc_c1存储到enc_c1.json文件中
                 const enc_c1_json = JSON.stringify(enc_c1);


                const enc_c1filepath = "D:\\\Fan\\A bishe\\project\\PRE_Enc\\enc_c1.json";

                fs.writeFile(enc_c1filepath, enc_c1_json, (err) => {

                    if (err) {
                        console.error('写入文件时出错：', err);
                        return;
                    }
                    console.log('C1数据已写入文件，路径为：', enc_c1filepath);
                });

                 /*
                 //读取遇到困难

                fs.readFile(enc_c1filepath, 'utf8', (err, loaded_c1) => {
                    if (err) {
                        console.error('读取文件时出错：', err);
                        return;
                    }
                        console.log("loaded_c1:",loaded_c1); // 输出应该是一个数组

                     const array1 = loaded_c1.slice(0,2);
                     console.log("array1:", array1); // 输出： ['e', '1']
                    // console.log(array2); // 输出： ['e', '2']
                    //console.log(array3); // 输出： ['e', '3']
                    //console.log(array4); // 输出： ['e', '1']
                    // console.log(array5); // 输出： ['e', '2']
                   // console.log(array6); // 输出： ['e', '3']
                    // console.log(array7); // 输出： ['e', '1']
                    // console.log(array8); // 输出： ['e', '2']

                });

                  */

                // 下面是reKey的生成和存储
                            const reKey = PRE.rekeyGen(AprivateKeyHex, BpublicKeyHex, {returnHex:true} );
                             console.log("reKey:",reKey);

                            // 将 reKey 存储到文件中
                            const rekeyfilepath = "D:\\Fan\\A bishe\\project\\PRE_Enc\\rekey.json";
                            // 将 mcl.G2 对象转换为字符串

                const reKey_json = JSON.stringify(reKey);
                fs.writeFile(rekeyfilepath, reKey_json, (err) => {
                                if (err) {
                                    console.error('写入文件时出错：', err);
                                    return;
                                }
                                console.log('reKey 已成功存储到文件中，路径为：', rekeyfilepath);
                            });
/*
                          // 从文件中读取 reKeyString，出现问题
                            fs.readFile(rekeyfilepath, 'utf8', (err, loaded_reKeyStr) => {
                                if (err) {
                                    console.error('读取文件时出错：', err);
                                    return;
                                }

                                // 将读取到的字符串转换为 mcl.G2 对象
                                const loadedReKey = mcl.deserializeHexStrToG2(loaded_reKeyStr);
                                console.log("rekey from File:",loadedReKey);

                                // 在这里使用 reKeyFromFile 进行后续操作
                            });

 */
                // 正确性测试部分
                //const decrypted = PRE.dec(encrypted1, AprivateKeyHex, params);
                //console.log("decrypted1:",decrypted);
                //console.log( decrypted === encKey1);



            });


        })


    });

/*

        //数组的分解

       // var array1 = enc_c1.slice(0,2);

        //console.log(array1); // 输出： ['e', '1']
       // console.log(array2); // 输出： ['e', '2']
        //console.log(array3); // 输出： ['e', '3']
        //console.log(array4); // 输出： ['e', '1']
       // console.log(array5); // 输出： ['e', '2']
        //console.log(array6); // 输出： ['e', '3']
       // console.log(array7); // 输出： ['e', '1']
       // console.log(array8); // 输出： ['e', '2']

*/


}).catch(err => {
    console.log(err)
});