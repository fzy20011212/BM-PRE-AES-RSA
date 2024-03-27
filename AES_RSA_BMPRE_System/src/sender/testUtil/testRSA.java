package sender.testUtil;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

import java.util.Scanner;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

import javax.crypto.Cipher;

import sender.encryptionUtil.BytesToHex;
import sender.encryptionUtil.RSAUtil;

public class testRSA {

	//待加密原文
	public static final String DATA = "123";

	public static void main(String[] args) throws Exception {
		Map<String, Object> keyMap = RSAUtil.initKey();

		RSAPublicKey rsaPublicKey = RSAUtil.getpublicKey(keyMap);
		RSAPrivateKey rsaPrivateKey = RSAUtil.getPrivateKey(keyMap);
		System.out.println("RSA PublicKey: \n" + rsaPublicKey);
		System.out.println("RSA PrivateKey:\n " + rsaPrivateKey);


		exportPublicKey(rsaPublicKey, "RSAKey/pk.pem");


		RSAPublicKey loadedPK = importPublicKey("RSAKey/pk.pem");
		System.out.println("Loaded RSA PublicKey: \n" + loadedPK);




		byte[] rsaResult = RSAUtil.encrypt(DATA.getBytes(), loadedPK);
		System.out.println(DATA + "====>>>> RSA 加密>>>>====" + BytesToHex.fromBytesToHex(rsaResult));


		byte[] plainResult = RSAUtil.decrypt(rsaResult, rsaPrivateKey);
		System.out.println(DATA + "====>>>> RSA 解密>>>>====" + BytesToHex.fromBytesToHex(plainResult));
		String plainResultString = new String(plainResult, StandardCharsets.UTF_8);
		System.out.println(DATA + "====>>>> RSA 解密>>>>====" + plainResultString);


	}

	// 导出公钥到文件
	public static void exportPublicKey(RSAPublicKey publicKey, String filePath) throws IOException {
		// 获取公钥的字节数组形式
		byte[] publicKeyBytes = publicKey.getEncoded();
		try (FileOutputStream fos = new FileOutputStream(filePath)) {
			// 将公钥字节数组写入文件
			fos.write(publicKeyBytes);
		}
		System.out.println("公钥已导出到 " + filePath);
	}

	// 从文件中导入公钥
	public static RSAPublicKey importPublicKey(String filePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		// 从文件中读取公钥字节数组
		byte[] publicKeyBytes = Files.readAllBytes(Paths.get(filePath));

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
		return (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);




	}
}



