package no.kantega.security.api.impl.dbuser.password;

import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

import java.util.Map;

/**
 * User: Sigurd Stendal
 * Date: 07.05.14
 */
public class PasswordHashManager implements ApplicationContextAware {

    private static final String DEFAULT_PASSWORDHASHER_BEAN_NAME = "defaultPasswordHasher";

    private ApplicationContext applicationContext;
    private PasswordCryptManager passwordCryptManager;

    public void setApplicationContext(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    public void setPasswordCryptManager(PasswordCryptManager passwordCryptManager) {
        this.passwordCryptManager = passwordCryptManager;
    }

    public PasswordHasher getPasswordHasher(String algorithm) {

        PasswordHasher hasher = null;

        // Search for PasswordHasher bean that supports this algorithm
        Map<String, PasswordHasher> map = applicationContext.getBeansOfType(PasswordHasher.class);
        for (PasswordHasher h : map.values()) {
            if (h.getAlgorithm().equals(algorithm)) {
                hasher = h;
            }
        }

        // Search for legacy PasswordCrypt beans
        if (hasher == null) {
            hasher = getLegacyPasswordCryptHasher(algorithm);
        }

        if (hasher == null) {
            throw new IllegalStateException("No password hasher supports the algorithm " + algorithm);
        }

        return hasher;
    }

    public PasswordHasher getDefaultPasswordHasher() {

        PasswordHasher hasher = null;
        if (applicationContext.containsBean(DEFAULT_PASSWORDHASHER_BEAN_NAME)) {
            hasher = applicationContext.getBean(DEFAULT_PASSWORDHASHER_BEAN_NAME, PasswordHasher.class);
        }
        // Search for legacy PasswordCrypt beans
        if (hasher == null) {
            hasher = getLegacyPasswordCryptHasher(null);
        }

        if (hasher == null) {
            throw new IllegalStateException("No bean with id 'defaultPasswordHasher' is defined. Please configure appropriately");
        }

        return hasher;
    }


    public PasswordHasher getLegacyPasswordCryptHasher(String id) {
        PasswordHasher passwordHasher = null;
        PasswordCrypt crypt = passwordCryptManager.getPasswordCrypt(id);
        if (crypt != null) {
            passwordHasher = new LegacyPasswordCryptPasswordHasher(id, crypt);
        }
        return passwordHasher;
    }

    public String getDefaultAlgorithm() {
        return getDefaultPasswordHasher().getAlgorithm();
    }


}
