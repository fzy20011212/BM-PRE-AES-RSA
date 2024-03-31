package receiver;

import java.io.*;
import receiver.encryptionUtil.HexToBytes;
import sender.encryptionUtil.AESUtil;
import sender.encryptionUtil.BytesToHex;
import sender.encryptionUtil.RSAUtil;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.IOException;
import java.nio.file.Files;
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


public class receiver_dataDec {

    public static void main(String[] args) throws Exception {
        // 读取DecKey 和 test.txt

        String DeKeyPath = "D:/Fan/A bishe/project/DecFiles/decKey.txt";
        try {
            // 读取文件的所有字节
            byte[] dekeybytes = Files.readAllBytes(Paths.get(DeKeyPath));
            // 将字节转换为字符串
            String decKey = new String(dekeybytes, StandardCharsets.UTF_8);
            // System.out.println("读取到的解密键为： " + decKey);
            String EncDataPath = "D:\\Fan\\A bishe\\project\\AES_RSA_BMPRE_System\\src\\server\\test.txt";

            try {
                // 读取文件的所有字节
                byte[] encdatabytes = Files.readAllBytes(Paths.get(EncDataPath));
                // 将字节转换为字符串
                String encData = new String(encdatabytes, StandardCharsets.UTF_8);


                // 读取RSA私钥
                RSAPrivateKey rsaPrivateKey = importPrivateKey();
                // System.out.println("私钥为：" + rsaPrivateKey);

                // 对DecKey解密得到AESKey
                // 要把DecKey从HexStr转换为Bytes
                byte[] AESKey = RSAUtil.decrypt(HexToBytes.fromHexToBytes(decKey), rsaPrivateKey);

                // 用AESKey对test.txt解密得到data
                byte[] plain = AESUtil.decryptAES(HexToBytes.fromHexToBytes(encData), AESKey);
                System.out.println(" 数据明文为: " + new String(plain));

                String plainResultString = new String(plain, StandardCharsets.UTF_8);

                //把明文写入文件

                Scanner scanner = new Scanner(System.in);

                // 提示用户输入字符串
                System.out.print("请输入保存文件的名称 例如：data.txt ：\n");

                // 读取用户输入的字符串
                String DATA = scanner.nextLine();


                // 关闭Scanner对象
                scanner.close();
                File dataFolder = new File("DecFiles");
                if (!dataFolder.exists()) {
                    dataFolder.mkdir();
                }


                File outputdata = new File(dataFolder, DATA);

                try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputdata))) {
                    writer.write(plainResultString);
                    System.out.println("\n已成功写入到：" + outputdata.getAbsolutePath());

                } catch (IOException e) {
                    e.printStackTrace();
                    System.out.println("error!");
                }



            } catch (IOException e) {
                e.printStackTrace();
            }


        } catch (IOException e) {
            e.printStackTrace();
        }


    }
    // 导出私钥到private.pem文件
    private static void exportPrivateKey(RSAPrivateKey privateKey) throws Exception {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
        FileOutputStream fos = new FileOutputStream("RSAKey/privatekey.pem");
        fos.write(spec.getEncoded());
        fos.close();
        System.out.println("私钥已导出到 RSAKey/privatekey.pem 文件中。");
    }

    // 从private.pem文件中导入私钥
    private static RSAPrivateKey importPrivateKey() throws Exception {
        byte[] privateKeyBytes = Files.readAllBytes(new File("RSAKey/privatekey.pem").toPath());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyBytes);
        return (RSAPrivateKey) keyFactory.generatePrivate(spec);
    }


}