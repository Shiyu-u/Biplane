package util;

import it.unisa.dia.gas.jpbc.Element;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.util.Random;

import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.security.SecureRandom;

public class CryptoUtil {
    /**
     * 获取哈希值
     *
     * @param mode    哈希模式
     * @param element 要哈希的值
     * @return 哈希过后的值
     */
    public static byte[] getHash(String mode, Element element) {
        byte[] hash_value = null;

        try {
            MessageDigest md = MessageDigest.getInstance(mode);
            hash_value = md.digest(element.toBytes());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return hash_value;
    }

    /**
     * 获取哈希值
     *
     * @param mode  哈希模式
     * @param bytes 要哈希的值
     * @return 哈希过后的值
     */
    public static byte[] getHash(String mode, byte[] bytes) {
        byte[] hash_value = null;

        try {
            MessageDigest md = MessageDigest.getInstance(mode);
            hash_value = md.digest(bytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return hash_value;
    }

    /**
     * ElGamal加密函数
     *
     * @param key  加密密钥
     * @param data 要加密的数据
     * @return 密文
     */
    public static Element[] ElGamalEncrypt(Element p, Element key, Element data) {
        int k = new Random().nextInt();
        Element[] secret = new Element[2];

        secret[0] = p.duplicate().pow(BigInteger.valueOf(k));
        secret[1] = data.duplicate().add(key.duplicate().pow(BigInteger.valueOf(k)));

        return secret;

    }

    /**
     * ElGamal解密函数
     *
     * @param key  密钥
     * @param data 密文
     * @return 明文
     */
    public static Element ElGamalDecrypt(Element key, Element[] data) {
        return data[1].sub(data[0].mulZn(key));
    }

    /**
     * AES加密函数
     *
     * @param key  加密密钥,128或256位
     * @param data 要加密的数据
     * @return 密文
     */
    public static byte[] AESEncrypt(byte[] key, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        String key_algorithm = "AES";
        Cipher cipher;
        cipher = Cipher.getInstance("AES");
        Key key1 = initKeyForAES(new String(key));
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key1.getEncoded(), key_algorithm));
        return cipher.doFinal(data);
    }

    /**
     * AES解密函数
     *
     * @param key  密钥
     * @param data 密文
     * @return 明文
     */
    public static byte[] AESDecrypt(byte[] key, byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        String key_algorithm = "AES";
        Cipher cipher;
        cipher = Cipher.getInstance("AES");
        Key key1 = initKeyForAES(new String(key));
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key1.getEncoded(), key_algorithm));
        return cipher.doFinal(data);
    }

    private static Key initKeyForAES(String key) throws NoSuchAlgorithmException {
        if (null == key || key.length() == 0) {
            throw new NullPointerException("key not is null");
        }
        SecretKeySpec key2;
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(key.getBytes());
        try {
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(128, random);
            SecretKey secretKey = kgen.generateKey();
            byte[] enCodeFormat = secretKey.getEncoded();
            key2 = new SecretKeySpec(enCodeFormat, "AES");
        } catch (NoSuchAlgorithmException ex) {
            throw new NoSuchAlgorithmException();
        }
        return key2;
    }


    public static ECPoint hashToP256(String input) throws NoSuchAlgorithmException {
        // Initialize Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());

        try {
            // Step 1: Hash the input using SHA-3
            MessageDigest digest = MessageDigest.getInstance("SHA3-256");
            byte[] hash = digest.digest(input.getBytes());

            // Step 2: Map the hash to a point on the P-256 elliptic curve
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
            ECPoint point = mapToP256(hash, ecSpec);

            return point;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static ECPoint mapToP256(byte[] hash, ECParameterSpec ecSpec) {
        BigInteger x = new BigInteger(1, hash);

        // Ensure x is in the valid range for P-256
        x = x.mod(ecSpec.getN());

        // Use x-coordinate to generate the corresponding y-coordinate
        ECPoint point = ecSpec.getG().multiply(x).normalize();

        return point;
    }

    public static ECPoint scalarMultiply(BigInteger scalar, ECPoint point) {
        // Initialize Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());

        try {
            // Get the P-256 elliptic curve parameters
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");

            // Perform scalar multiplication
            ECPoint result = point.multiply(scalar).normalize();

            return result;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static Element stringHashToG (String input, Field field, Pairing pairing) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        byte[] hash = digest.digest(input.getBytes());

        // Map the hashed bytes to a field element
        Element fieldElement = field.newElementFromHash(hash, 0, hash.length).getImmutable();

        // Map the field element to a point on the elliptic curve
        Element resultElement = pairing.getG1().newElement().set(fieldElement).getImmutable();

        return resultElement;
    }
}
