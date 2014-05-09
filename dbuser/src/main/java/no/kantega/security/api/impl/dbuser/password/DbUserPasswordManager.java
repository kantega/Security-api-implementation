package no.kantega.security.api.impl.dbuser.password;

/*
 * Copyright 2009 Kantega AS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import no.kantega.security.api.common.SystemException;
import no.kantega.security.api.identity.Identity;
import no.kantega.security.api.password.PasswordManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * User: Anders Skar, Kantega AS
 * Date: Jan 15, 2007
 * Time: 6:33:38 PM
 */
public class DbUserPasswordManager implements PasswordManager {

    private String domain;
    private Logger log = LoggerFactory.getLogger(getClass());
    private PasswordHashManager passwordHashManager;
    private PasswordDao passwordDao;

    public boolean verifyPassword(Identity identity, String password) throws SystemException {
        String dbPassword = passwordDao.readPasswordFromDatabase(identity);
        if (dbPassword == null) return false;

        PasswordHash hashData = PasswordHashJsonEncoder.decode(dbPassword);
        String hashedPassword = password;
        for (PasswordHashAlgorithm algorithm : hashData.getAlgorithms()) {
            PasswordHasher hasher = passwordHashManager.getPasswordHasher(algorithm.getId());
            hashedPassword = hasher.hashPassword(hashedPassword, algorithm).getHash();
        }

        boolean correctPassword = hashData.getHash().equals(hashedPassword);
        if (correctPassword) {
            log.debug("Password verified for userid: {}", identity.getUserId());
        } else {
            log.debug("Password verification failed for userid: {}", identity.getUserId());
        }

        return correctPassword;
    }

    public void setPassword(Identity identity, String password, String password2) throws SystemException {
        if (!password.equals(password2)) return;

        PasswordHasher hasher = passwordHashManager.getDefaultPasswordHasher();
        PasswordHash hashData = hasher.hashPassword(password);
        String hashDataAsString = PasswordHashJsonEncoder.encode(hashData);

        passwordDao.updatePasswordInDatabase(identity, hashDataAsString);

        passwordDao.updateMechFieldInDatabase(identity);

        log.debug("Password set for userid: {}", identity.getUserId());
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public boolean supportsPasswordChange() {
        return true;
    }

    public void setPasswordHashManager(PasswordHashManager passwordHashManager) {
        this.passwordHashManager = passwordHashManager;
    }

    public void setPasswordDao(PasswordDao passwordDao) {
        this.passwordDao = passwordDao;
    }
}
