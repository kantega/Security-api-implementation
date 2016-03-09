package no.kantega.security.api.impl.dbuser.password;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Will rehash all passwords in the database with the current default PasswordHasher
 */
public class DbUserPasswordRehasher {

    private Logger log = LoggerFactory.getLogger(getClass());

    private String domain;
    private PasswordDao passwordDao;
    private PasswordHashManager passwordHashManager;
    private PasswordCryptManager passwordCryptManager;

    public void rehashAll() {
        if(Boolean.parseBoolean(System.getProperty("DbUserPasswordRehasher.skipRehashAll", "false"))){
            log.info("Skipping rehashAll");
            return;
        }
        log.info("Looking for passwords that needs re-hashing");

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

            List<PasswordHashAlgorithm> algorithms = hashData.getAlgorithms();
            if (!algorithms.get(algorithms.size() - 1).getId().equals(defaultAlgorithm)) {
                log.info("Found a password that needs re-hashing; userId=" + userId + "; previous hash algorithm=" + algorithms.get(0).getId());
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

        PasswordHashAlgorithm algorithm = new PasswordHashAlgorithm();
        algorithm.setId(crypt.getId());

        // Why we store the hash as salt: If the password was salted, the salt was appended to the hash string before it was saved.
        // Only the PasswordCrypt implementation knows if there was a salt and how to extract the salt from the hash. So we store the hash
        // as "salt" and provides this value to the PasswordCrypt implementation. The implementation will either ignore it or use it.
        algorithm.put("salt", hashString);
        hashData.addAlgorithm(algorithm);

        return hashData;
    }
}
