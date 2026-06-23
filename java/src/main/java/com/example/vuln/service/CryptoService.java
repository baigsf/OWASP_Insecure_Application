package com.example.vuln.service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Random;

public class CryptoService {

    private static final String HARDCODED_KEY = "0123456789abcdef";

    // VULNERABILITY: Hardcoded cryptographic key
    public byte[] encryptHardcodedKey(byte[] data) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(HARDCODED_KEY.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(data);
    }

    // VULNERABILITY: ECB mode (insecure)
    public byte[] encryptEcb(byte[] data, byte[] key) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(data);
    }

    // VULNERABILITY: Weak algorithm DES
    public byte[] encryptDes(byte[] data, byte[] key) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(data);
    }

    // VULNERABILITY: Weak hashing algorithm MD5
    public String hashMd5(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(input.getBytes());
        return new BigInteger(1, digest).toString(16);
    }

    // VULNERABILITY: Weak hashing algorithm SHA1
    public String hashSha1(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA1");
        byte[] digest = md.digest(input.getBytes());
        return Base64.getEncoder().encodeToString(digest);
    }

    // VULNERABILITY: Insecure random number generator
    public String generateTokenInsecure() {
        Random random = new Random();
        return String.valueOf(random.nextInt());
    }

    // VULNERABILITY: Predictable seed
    public String generateTokenPredictable() {
        Random random = new Random(System.currentTimeMillis());
        return String.valueOf(random.nextInt());
    }

    // VULNERABILITY: Short key
    public byte[] generateShortKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(64);
        return keyGen.generateKey().getEncoded();
    }
}
