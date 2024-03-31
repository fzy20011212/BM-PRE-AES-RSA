package receiver.encryptionUtil;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class HexToBytes {

    public static byte[] fromHexToBytes(String hexString) {
        // 检查十六进制字符串的长度是否为偶数
        if (hexString.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string length must be even.");
        }

        // 计算字节数组的长度
        int len = hexString.length() / 2;
        byte[] resultBytes = new byte[len];

        // 将每两个字符转换为一个字节
        for (int i = 0; i < len; i++) {
            int highNibble = Character.digit(hexString.charAt(i * 2), 16);
            int lowNibble = Character.digit(hexString.charAt(i * 2 + 1), 16);
            if (highNibble == -1 || lowNibble == -1) {
                throw new IllegalArgumentException("Invalid hex string: " + hexString);
            }
            resultBytes[i] = (byte) ((highNibble << 4) + lowNibble);
        }
        return resultBytes;
    }

    public static void main(String[] args) {
        String hexString = "313233";
        byte[] resultBytes = fromHexToBytes(hexString);
        String plainResultString = new String(resultBytes, StandardCharsets.UTF_8);
        System.out.println(Arrays.toString(resultBytes));
        System.out.println(plainResultString);
    }
}