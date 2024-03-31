package sender;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.io.*;
import sender.encryptionUtil.AESUtil;
import sender.encryptionUtil.BytesToHex;
import sender.encryptionUtil.RSAUtil;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;



public class sender_dataEnc {

    //待加密原文
    //public static final String DATA = "";


    public static void main(String[] args) throws Exception {
        /*
        下面是提示用户输入需要加密的数据，数据文件名称和密钥文件名称
         */
        Scanner scanner = new Scanner(System.in);

        // 提示用户输入字符串
        System.out.print("请输入需要加密的数据：\n");

        // 读取用户输入的字符串
        String DATA = scanner.nextLine();

        // 输出用户输入的字符串以验证
        //System.out.println("您输入的数据是：" + DATA);

        System.out.print("请输入加密数据文件的名称（例如：test.txt）：\n");
        String fileName = scanner.nextLine();
        //System.out.println("您输入的文件名为：" + fileName);

        System.out.print("请输入加密密钥文件的名称（例如：enckey.txt）：\n");
        String keyName = scanner.nextLine();

        // 关闭Scanner对象
        scanner.close();

        // AES加密部分
        byte[] aesKey = AESUtil.initKey();
        // System.out.println("AES key:" + BytesToHex.fromBytesToHex(aesKey) + "\n");
        // 获取AES密钥
        byte[] encrypt = AESUtil.encryptAES(DATA.getBytes(), aesKey);
        // System.out.println("加密后的Bytes类型为：" + encrypt);
        // System.out.println("加密后的数据为:" + BytesToHex.fromBytesToHex(encrypt) + "\n");
        //AES加密

        String filepath = "D:\\Fan\\A bishe\\project\\AES_RSA_BMPRE_System\\src\\server\\" + fileName;
        Path outputfilePath = Paths.get(filepath);

        try (BufferedWriter writer = Files.newBufferedWriter(outputfilePath)) {
            writer.write(BytesToHex.fromBytesToHex(encrypt));
            System.out.println("\n加密数据已成功写入到：" + outputfilePath.toAbsolutePath().toString());
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("error!");
        }
/*
        File outputFile = new File(encdataFolder, fileName);

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile))) {
            writer.write(BytesToHex.fromBytesToHex(encrypt));
            System.out.println("\n加密数据已成功写入到：" + outputFile.getAbsolutePath());

        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("error!");
        }

 */

/*
        Map<String, Object> keyMap = RSAUtil.initKey();
        RSAPublicKey rsaPublicKey = RSAUtil.getpublicKey(keyMap);
        RSAPrivateKey rsaPrivateKey = RSAUtil.getPrivateKey(keyMap);
        System.out.println("RSA public key:" + rsaPublicKey + "\n");
        System.out.println("RSA private key:" + rsaPrivateKey + "\n");
        //RSA公私钥生成


 */

        /*
        String keyFolder = "RSAKey";
        File RSAfolder = new File(keyFolder);
        if (!RSAfolder.exists()) {
            RSAfolder.mkdir();
        }
        File RSAFile = new File(RSAfolder, fileName);

        exportPublicKey(rsaPublicKey, "RSAKey/publickey.pem");
        exportPrivateKey(rsaPrivateKey, "RSAKey/privatekey.pem");

         */



        // RSA公钥的读取以及RSA加密
        RSAPublicKey rsaPublicKey = importPublicKey("RSAKey/publickey.pem");


        byte[] rsaResult = RSAUtil.encrypt(aesKey, rsaPublicKey);
        // System.out.println("AESKey ====>>> RSA >>>===" + BytesToHex.fromBytesToHex(rsaResult) + "\n");
        // RSA加密

/*
        byte[] plainResult = RSAUtil.decrypt(rsaResult, rsaPrivateKey);
        //String palinResultString = new String(plainResult,StandardCharsets.UTF_8);
        System.out.println(" Decrypted AESKey:" + BytesToHex.fromBytesToHex(plainResult) + "\n");
        //RSA解密
        */


        //把加密密钥写入文件
        File enckeyFolder = new File("enckey");
        if (!enckeyFolder.exists()) {
            enckeyFolder.mkdir();
        }


        File outputKey = new File(enckeyFolder, keyName);

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputKey))) {
            writer.write(BytesToHex.fromBytesToHex(rsaResult));
            System.out.println("\n加密的AES密钥已成功写入到：" + outputKey.getAbsolutePath());

        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("error!");
        }




    }

    // 导出公钥到文件方法
    public static void exportPublicKey(RSAPublicKey publicKey, String filePath) throws IOException {
        // 获取公钥的字节数组形式
        byte[] publicKeyBytes = publicKey.getEncoded();
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            // 将公钥字节数组写入文件
            fos.write(publicKeyBytes);
        }
        System.out.println("公钥已导出到 " + filePath);
    }
    // 导出私钥到private.pem文件
    private static void exportPrivateKey(RSAPrivateKey privateKey, String filePath) throws Exception {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
        FileOutputStream fos = new FileOutputStream(filePath);
        fos.write(spec.getEncoded());
        fos.close();
        System.out.println(" 私钥已导出到" + filePath);
    }

    // 从文件中导入公钥方法
    public static RSAPublicKey importPublicKey(String filePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        // 从文件中读取公钥字节数组
        byte[] publicKeyBytes = Files.readAllBytes(Paths.get(filePath));

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        return (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);

    }
}


