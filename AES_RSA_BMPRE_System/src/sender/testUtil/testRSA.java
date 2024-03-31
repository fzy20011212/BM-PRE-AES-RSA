package sender.testUtil;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
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
		// 将私钥导出到private.pem文件
		exportPrivateKey(rsaPrivateKey);

		// 从private.pem文件中导入私钥
		RSAPrivateKey loadedSK = importPrivateKey();

		RSAPublicKey loadedPK = importPublicKey("RSAKey/pk.pem");
		System.out.println("Loaded RSA PublicKey: \n" + loadedPK);
		System.out.println("Loaded RSA PrivateKey: \n" + loadedSK);




		byte[] rsaResult = RSAUtil.encrypt(DATA.getBytes(), loadedPK);
		System.out.println(DATA + "====>>>> RSA 加密>>>>====" + BytesToHex.fromBytesToHex(rsaResult));


		byte[] plainResult = RSAUtil.decrypt(rsaResult, loadedSK);
		System.out.println(DATA + "plainResult的byte形式为：" + Arrays.toString(plainResult));
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
	// 导出私钥到private.pem文件
	private static void exportPrivateKey(RSAPrivateKey privateKey) throws Exception {
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
		FileOutputStream fos = new FileOutputStream("RSAKey/sk.pem");
		fos.write(spec.getEncoded());
		fos.close();
		System.out.println("私钥已导出到 RSAKey/sk.pem 文件中。");
	}

	// 从private.pem文件中导入私钥
	private static RSAPrivateKey importPrivateKey() throws Exception {
		byte[] privateKeyBytes = Files.readAllBytes(new File("RSAKey/sk.pem").toPath());
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyBytes);
		return (RSAPrivateKey) keyFactory.generatePrivate(spec);
	}
}



