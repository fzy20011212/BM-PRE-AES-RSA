const PRE = require('./pre.js');
const fs = require('fs');
const readline = require('readline');
const mcl = require('mcl-wasm');
const prompt = require('prompt-sync')();

PRE.init({g: "The generator for G1", h:"The generator for G2", returnHex:false}).then(params => {


    //const filePathA = 'D:\\\\Fan\\\\A bishe\\\\project\\\\PREKey\\\\A_key.txt';
    //const filePathB = 'D:\\\\Fan\\\\A bishe\\\\project\\\\PREKey\\\\B_key.txt';
    const rekeypath = 'D:\\Fan\\A bishe\\project\\PRE_Enc\\rekey.json';

    /*fs.readFile(filePathA, 'utf8', (err, data) => {
        if (err) {
            console.error('读取文件时出错：', err);
            return;
        }
        // 将文件中的内容分割成私钥和公钥字符串
        const [AprivateKeyString, ApublicKeyString] = data.trim().split('\n');
        // 提取私钥和公钥的十六进制表示
        const AprivateKeyHex = AprivateKeyString.split(':')[1].trim();
        const ApublicKeyHex = ApublicKeyString.split(':')[1].trim();

     */
    /*
            fs.readFile(filePathB, 'utf8', (err, data) => {
                if (err) {
                    console.error("error:", err);
                }
                const [BprivateKeyString, BpublicKeyString] = data.trim().split('\n');
                const BprivateKeyHex = BprivateKeyString.split(':')[1].trim();
                const BpublicKeyHex = BpublicKeyString.split(':')[1].trim();

     */

    fs.readFile(rekeypath, 'utf8', (err, data) => {
        if (err) {
            console.log('出错啦：', err);
            return;
        }
        const reKey = JSON.parse(data);

        const filepath = 'D:\\Fan\\A bishe\\project\\PRE_Enc\\enc_c1.json';

        fs.readFile(filepath, 'utf8', (err, data) => {
            if (err) {
                console.log('出错啦：', err);
                return;
            }
            const enc_c1 = JSON.parse(data);

            //let enc_c1 = new Array('417dad67b8a0afcfe130dcc0a36f377d8665443c72b56505ef2c4cd1be29de2632ff29f1f9f734d84970fde72cec7f94', 'fe475e2d9e1f50e222e1f7e076b0c8508908afa37fd3504db242610decb7fe53', '2a4fe607a7888944896d794767d7977f6d9d732bfdee26a60c3b8e1403be70877d379cd4c99be4d2df6979c999c23c81', 'eee929d5250a8eb5d5b7a8602267b17d9d7fe33477be4d9d85d68a8551f0dc18', '76429f2f5da848ceac709d63af74d4068b87954090420dee73fe571461610eecdcf281cef5480bdc0a9fa08e8e484b92', 'a0faf9ba5c6b44f4f79293d7bba9c80c279a0f854de9263141b3959cf3281e2a', '23fb0515e1e225ae904141b7c9aabb335e940a87602473d39e1d17b63d9c2d662adef83a7f5eccc4ba407bf3d0e52c0b', 'd301588491512526a2660e1171c98e63a1c84fe44e996ec1879cdd130fa26f67', 'b096ebd85dd127bc31da1ef39e0ddcc6cc3946a984adbdbc4def471a4f08b2dc03ef93bb182f7935ecbb7473c22c1818', '310880f6a2840904a0065988bcfdcada8f0219ab4d844a1be18e642b53404321', 'b80ff285a265665b62f0cce88a42853e21dc6496f0bab0020c75fccf4660c208b0fde921a78f6fc19fbfcd76d78f1198', '4b87b65ae7364b960e624d199a86f80cd386e04095dd7dc14b0e431cc02ea02c', '5e51bf91157f14c05d0c744cedb6a67a6bdb53e48864ca611f276380faa3cf23bd8c2895abda8e37afa3228beb89878b', 'fe8497a44194bcb9cd3fd846a1a6c3c08e6887080aab40de24ce7d5c6fc17210', '3b9b74d8f29faa52f6e42b5eb49206e9a7975b32ef0571fca99a60d05b027f73d9ca002776450d6fff3108c329eebe18', '3a73dddd372e97040ffc29a1ec9b650c1496668834ebf66fdaa480d599a26a45')
            let array1 = enc_c1.slice(0, 2);
            //console.log("c11:",array1);
            let array2 = enc_c1.slice(2, 4);
            let array3 = enc_c1.slice(4, 6);
            let array4 = enc_c1.slice(6, 8);
            let array5 = enc_c1.slice(8, 10);
            let array6 = enc_c1.slice(10, 12);
            let array7 = enc_c1.slice(12, 14);
            let array8 = enc_c1.slice(14, 16);
            const reEncrypted1 = PRE.reEnc(array1, reKey, {returnHex: true});
            //console.log("re encrypted:",reEncrypted1);
            const reEncrypted2 = PRE.reEnc(array2, reKey, {returnHex: true});
            const reEncrypted3 = PRE.reEnc(array3, reKey, {returnHex: true});
            const reEncrypted4 = PRE.reEnc(array4, reKey, {returnHex: true});
            const reEncrypted5 = PRE.reEnc(array5, reKey, {returnHex: true});
            const reEncrypted6 = PRE.reEnc(array6, reKey, {returnHex: true});
            const reEncrypted7 = PRE.reEnc(array7, reKey, {returnHex: true});
            const reEncrypted8 = PRE.reEnc(array8, reKey, {returnHex: true});


            const reEnc = [...reEncrypted1, ...reEncrypted2, ...reEncrypted3, ...reEncrypted4, ...reEncrypted5, ...reEncrypted6, ...reEncrypted7, ...reEncrypted8];
            console.log("reEnc:", reEnc);

            // 下面是存储到reEnc.json文件中
            const reEnc_json = JSON.stringify(reEnc);


            const reEncfilepath = "D:\\Fan\\A bishe\\project\\AES_RSA_BMPRE_System\\src\\server\\reEnc.json";

            fs.writeFile(reEncfilepath, reEnc_json, (err) => {

                if (err) {
                    console.error('写入文件时出错：', err);
                    return;
                }
                console.log('reEnc数据已写入文件,路径为：', reEncfilepath);
            });
        });

    });
    //const reKey = PRE.rekeyGen(AprivateKeyHex, BpublicKeyHex, {returnHex:true} );

    // 读取enc_c1，从enc_c1.json,当server2sender重跑时这里要更新




    // });

    // });

}).catch(err => {
    console.log(err)
});