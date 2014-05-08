package no.kantega.security.api.impl.dbuser.password;

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

/**
 * Wrapper over legacy PasswordCrypt implementations
 *
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
        Map<String, Object> algorithm = new HashMap<>();
        algorithm.put("id", algorithmName);
        return hashPassword(password, algorithm);
    }

    @Override
    public PasswordHash hashPassword(String password, Map<String, Object> algorithm) {

        try {
            byte[] salt = (byte[]) algorithm.get("salt");

            String hash;
            if(salt != null) {
                hash = passwordCrypt.crypt(password, new String(salt));
            } else {
                hash = passwordCrypt.crypt(password);
            }

            PasswordHash hashData = new PasswordHash();
            hashData.setHash(hash);
            hashData.addAlgorithm(algorithm);
            return hashData;


        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Failed ti hash password. Algorithm not supported.", e);
        }

    }

    @Override
    public String getAlgorithm() {
        return algorithmName;
    }
}
