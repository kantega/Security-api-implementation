package no.kantega.security.api.impl.dbuser.password;

import java.security.NoSuchAlgorithmException;

/**
 * Wrapper over legacy PasswordCrypt implementations
 * <p/>
 * User: Sigurd Stendal
 * Date: 07.05.14
 */
public class LegacyPasswordCryptPasswordHasher implements PasswordHasher {

    private String algorithmName;
    private PasswordCrypt passwordCrypt;

    public LegacyPasswordCryptPasswordHasher(String algorithmName, PasswordCrypt passwordCrypt) {
        this.algorithmName = algorithmName;
        this.passwordCrypt = passwordCrypt;
    }

    @Override
    public PasswordHash hashPassword(String password) {
        PasswordHashAlgorithm algorithm = new PasswordHashAlgorithm();
        algorithm.setId(algorithmName);
        return hashPassword(password, algorithm);
    }

    @Override
    public PasswordHash hashPassword(String password, PasswordHashAlgorithm algorithm) {

        try {
            String salt = (String) algorithm.get("salt");

            String hash;
            if (salt != null) {
                hash = passwordCrypt.crypt(password, salt);
            } else {
                hash = passwordCrypt.crypt(password);
            }

            PasswordHash hashData = new PasswordHash();
            hashData.setHash(hash);
            hashData.addAlgorithm(algorithm);
            return hashData;


        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Failed to hash password. Algorithm not supported.", e);
        }

    }

    @Override
    public String getAlgorithm() {
        return algorithmName;
    }
}
