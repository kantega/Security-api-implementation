package no.kantega.security.api.impl.dbuser.password;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

/**
 * User: Sigurd Stendal
 * Date: 06.05.14
 */
public class Pbkdf2WithHmacSha1PasswordHasher implements PasswordHasher {

    private static final int SALT_LENGTH = 16;
    private static final int KEY_LENGTH = 64 * 8;
    private static final String ALGORITHM = "PBKDF2WithHmacSha1";

    @Override
    public PasswordHash hashPassword(String password) {
        int iterations = 1000;
        byte[] salt = createSalt();

        Map<String, Object> algorithm = new HashMap<>();
        algorithm.put("id", ALGORITHM);
        algorithm.put("iterations", iterations);
        algorithm.put("salt", Hex.encodeHexString(salt));

        return hashPassword(password, algorithm);
    }

    @Override
    public PasswordHash hashPassword(String password, Map<String, Object> algorithm) {

        if(!ALGORITHM.equals(algorithm.get("id"))) {
            throw new IllegalArgumentException("This password hasher is unable to hash password using algorithm " + algorithm.get("id"));
        }

        int iterations = (int) algorithm.get("iterations");
        byte[] salt;
        try {
            salt = Hex.decodeHex(((String) algorithm.get("salt")).toCharArray());
        } catch (DecoderException e) {
            throw new RuntimeException("Failed to decode salt from hex format", e);
        }

        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, KEY_LENGTH);
        SecretKeyFactory skf = getSecretKeyFactory();
        byte[] hash = generateHash(spec, skf);

        PasswordHash hashData = new PasswordHash();
        hashData.setHash(Hex.encodeHexString(hash));
        hashData.addAlgorithm(algorithm);
        return hashData;
    }

    @Override
    public String getAlgorithm() {
        return ALGORITHM;
    }

    private static byte[] createSalt() {
        SecureRandom sr = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH];
        sr.nextBytes(salt);
        return salt;
    }

    private static SecureRandom getSecureRandom() {
        try {
            return SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Unable to create SecureRandom", e);
        }
    }

    private static SecretKeyFactory getSecretKeyFactory() {
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Unable to create SecretKeyFactory", e);
        }
    }

    private byte[] generateHash(PBEKeySpec spec, SecretKeyFactory skf) {
        try {
            return skf.generateSecret(spec).getEncoded();
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException("Failed to generate password hash", e);
        }
    }

}
