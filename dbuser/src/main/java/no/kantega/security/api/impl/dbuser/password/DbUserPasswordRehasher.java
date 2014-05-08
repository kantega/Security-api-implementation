package no.kantega.security.api.impl.dbuser.password;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Will rehash all passwords in the database with the current default PasswordHasher
 * <p/>
 * User: Sigurd Stendal
 * Date: 07.05.14
 */
public class DbUserPasswordRehasher {

    private String domain;
    private PasswordDao passwordDao;
    private PasswordHashManager passwordHashManager;
    private PasswordCryptManager passwordCryptManager;

    public void rehashAll() {

        String defaultAlgorithm = passwordHashManager.getDefaultAlgorithm();
        List<String> usersWithPasswords = passwordDao.findUsersWithPasswords(domain);

        for (String userId : usersWithPasswords) {
            String hashString = passwordDao.getPasswordHash(domain, userId);
            boolean hashDataIsChanged = false;

            PasswordHash hashData;
            if (!hashString.startsWith("{")) {
                String algorithmName = passwordDao.getPasswordHashAlgorithm(domain, userId);
                PasswordCrypt crypt = passwordCryptManager.getPasswordCrypt(algorithmName);

                hashData = wrapInPasswordHash(hashString, crypt);
                hashDataIsChanged = true;
            } else {
                hashData = PasswordHashJsonEncoder.decode(hashString);
            }

            if (!hashData.getAlgorithms().get(0).get("id").equals(defaultAlgorithm)) {
                rehash(hashData);
                hashDataIsChanged = true;
            }

            if (hashDataIsChanged) {
                hashString = PasswordHashJsonEncoder.encode(hashData);
                passwordDao.storePasswordHash(domain, userId, hashString);
            }
        }
    }

    public void setPasswordDao(PasswordDao passwordDao) {
        this.passwordDao = passwordDao;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public void setPasswordHashManager(PasswordHashManager passwordHashManager) {
        this.passwordHashManager = passwordHashManager;
    }

    public void setPasswordCryptManager(PasswordCryptManager passwordCryptManager) {
        this.passwordCryptManager = passwordCryptManager;
    }

    private void rehash(PasswordHash hashData) {
        PasswordHasher hasher = passwordHashManager.getDefaultPasswordHasher();
        PasswordHash newHashData = hasher.hashPassword(hashData.getHash());
        hashData.setHash(newHashData.getHash());
        hashData.addAlgorithm(newHashData.getAlgorithms().get(0));
    }

    private PasswordHash wrapInPasswordHash(String hashString, PasswordCrypt crypt) {
        PasswordHash hashData = new PasswordHash();
        hashData.setHash(hashString);

        Map<String, Object> algorithm = new HashMap<>();
        algorithm.put("id", crypt.getId());
        hashData.addAlgorithm(algorithm);

        return hashData;
    }
}
