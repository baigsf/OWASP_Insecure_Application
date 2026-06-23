package com.example.vuln.service;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Random;

public class ExtraCryptoService {

    private static final String KEY = "hardcodedkey1234";

    // VULNERABILITY: Hardcoded key
    public byte[] encryptAesEcb(byte[] data) throws Exception {
        SecretKeySpec spec = new SecretKeySpec(KEY.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, spec);
        return cipher.doFinal(data);
    }

    // VULNERABILITY: DES weak algorithm
    public byte[] encryptDesWeak(byte[] data) throws Exception {
        SecretKeySpec spec = new SecretKeySpec(KEY.getBytes(), "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, spec);
        return cipher.doFinal(data);
    }

    // VULNERABILITY: MD5 hashing
    public String md5Hash(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return new BigInteger(1, md.digest(input.getBytes())).toString(16);
    }

    // VULNERABILITY: SHA1 hashing
    public String sha1Hash(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA1");
        return new BigInteger(1, md.digest(input.getBytes())).toString(16);
    }

    // VULNERABILITY: Insecure random
    public int insecureRandom() {
        return new Random().nextInt();
    }
}
