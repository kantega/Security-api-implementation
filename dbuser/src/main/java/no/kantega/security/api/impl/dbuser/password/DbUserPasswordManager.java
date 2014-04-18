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
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.jdbc.BadSqlGrammarException;
import org.springframework.jdbc.core.support.JdbcDaoSupport;

import java.security.NoSuchAlgorithmException;

/**
 * User: Anders Skar, Kantega AS
 * Date: Jan 15, 2007
 * Time: 6:33:38 PM
 */
public class DbUserPasswordManager extends JdbcDaoSupport implements PasswordManager {
    private static final String SOURCE = "security.DbUserPasswordManager";

    private String domain;
    private Logger log = LoggerFactory.getLogger(getClass());
    private PasswordCryptManager passwordCryptManager;
    private String defaultCreateHash;


    public boolean verifyPassword(Identity identity, String password) throws SystemException {
        String dbPassword = null;
        String dbHash = null;

        try {
            dbPassword = getJdbcTemplate().queryForObject("SELECT Password FROM dbuserpassword WHERE Domain = ? AND UserId = ?", new Object[] { identity.getDomain(), identity.getUserId() }, String.class);
            try {
                dbHash = getJdbcTemplate().queryForObject("SELECT HashMech FROM dbuserpassword WHERE Domain = ? AND UserId = ?", new Object[] { identity.getDomain(), identity.getUserId() }, String.class);
            } catch (BadSqlGrammarException e) {
                // HashMech field does not exist, so defalt will be used
                dbHash = null;
            }
        } catch (IncorrectResultSizeDataAccessException e) {
            return false;
        }

        String cryptPW = null;
        try {
            // supply dbPassword to get correct salt
            PasswordCrypt passwordCrypt = passwordCryptManager.getPasswordCrypt(dbHash);
            cryptPW = passwordCrypt.crypt(password, dbPassword);
        } catch (NoSuchAlgorithmException e) {
            throw new SystemException(SOURCE, e);
        }

        boolean correctPassword = dbPassword.equals(cryptPW);
        if (correctPassword) {
            log.debug("Password verified for userid: {}", identity.getUserId());
        } else {
            log.debug("Password verification failed for userid: {}", identity.getUserId());
        }

        return correctPassword;
    }

    public void setPassword(Identity identity, String password, String password2) throws SystemException {
        if (!password.equals(password2)) return;

        // passwordCryptManager the password - salt is autogenereated
        String cryptPW = null;
        boolean supportsMech = true;
        PasswordCrypt passwordCrypt = null;
        try {
            passwordCrypt = passwordCryptManager.getPasswordCrypt(defaultCreateHash);

            try {
                getJdbcTemplate().queryForObject("select count(HashMech) from dbuserpassword", Integer.class);
            } catch (BadSqlGrammarException e) {
                // Use default/fallback mechanism
                supportsMech = false;
                passwordCrypt = passwordCryptManager.getPasswordCrypt(null);
            }


            cryptPW = passwordCrypt.crypt(password);
        } catch (NoSuchAlgorithmException e) {
            throw new SystemException(SOURCE, e);
        }

        int count = getJdbcTemplate().queryForObject("SELECT COUNT(*) FROM dbuserpassword WHERE Domain = ? AND UserId = ?", Integer.class,
                identity.getDomain(), identity.getUserId());
        if (count == 0) {
            // New user, without password
            getJdbcTemplate().update("INSERT INTO dbuserpassword (Domain, UserId, Password) VALUES (?, ?, ?)",
                    identity.getDomain(), identity.getUserId(), cryptPW);
        } else {
            getJdbcTemplate().update("UPDATE dbuserpassword SET Password = ? WHERE Domain = ? AND UserId = ?",
                    cryptPW, identity.getDomain(), identity.getUserId());
        }

        if(supportsMech) {
            getJdbcTemplate().update("UPDATE dbuserpassword SET HashMech = ? WHERE Domain = ? AND UserId = ?",
                    passwordCrypt.getId(), identity.getDomain(), identity.getUserId());
        }

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

    public void setPasswordCryptManager(PasswordCryptManager passwordCryptManager) {
        this.passwordCryptManager = passwordCryptManager;
    }

    public void setDefaultCreateHash(String defaultCreateHash) {
        this.defaultCreateHash = defaultCreateHash;
    }
}
