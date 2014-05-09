package no.kantega.security.api.impl.dbuser.password;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

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

        PasswordHashAlgorithm algorithm = new PasswordHashAlgorithm();
        algorithm.setId(ALGORITHM);
        algorithm.put("iterations", iterations);
        algorithm.put("salt", Hex.encodeHexString(salt));

        return hashPassword(password, algorithm);
    }

    @Override
    public PasswordHash hashPassword(String password, PasswordHashAlgorithm algorithm) {

        if (!ALGORITHM.equals(algorithm.getId())) {
            throw new IllegalArgumentException("This password hasher is unable to hash password using algorithm " + algorithm.getId());
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
