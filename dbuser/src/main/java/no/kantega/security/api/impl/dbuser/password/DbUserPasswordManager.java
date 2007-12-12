package no.kantega.security.api.impl.dbuser.password;

import no.kantega.security.api.password.PasswordManager;
import no.kantega.security.api.identity.Identity;
import no.kantega.security.api.common.SystemException;

import javax.sql.DataSource;

import org.springframework.jdbc.core.support.JdbcDaoSupport;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.apache.log4j.Logger;

import java.security.NoSuchAlgorithmException;

/**
 * User: Anders Skar, Kantega AS
 * Date: Jan 15, 2007
 * Time: 6:33:38 PM
 */
public class DbUserPasswordManager extends JdbcDaoSupport implements PasswordManager {
    private static final String SOURCE = "security.DbUserPasswordManager";

    private String domain;
    private Logger log = Logger.getLogger(getClass());


    public boolean verifyPassword(Identity identity, String password) throws SystemException {
        String dbPassword = null;
        try {
            dbPassword = (String) getJdbcTemplate().queryForObject("SELECT Password FROM dbuserpassword WHERE Domain = ? AND UserId = ?", new Object[] { identity.getDomain(), identity.getUserId() }, String.class);
        } catch (IncorrectResultSizeDataAccessException e) {
            return false;
        }

        String cryptPW = null;
        try {
            // supply dbPassword to get correct salt
            cryptPW = MD5Crypt.crypt(password, dbPassword);
        } catch (NoSuchAlgorithmException e) {
            throw new SystemException(SOURCE, e);
        }

        boolean correctPassword = dbPassword.equals(cryptPW);
        if (correctPassword) {
            log.debug("Password verified for userid:" + identity.getUserId());
        } else {
            log.debug("Password verification failed for userid:" + identity.getUserId());
        }

        return correctPassword;
    }

    public void setPassword(Identity identity, String password, String password2) throws SystemException {
        if (!password.equals(password2)) return;

        // crypt the password - salt is autogenereated
        String cryptPW = null;
        try {
            cryptPW = MD5Crypt.crypt(password);
        } catch (NoSuchAlgorithmException e) {
            throw new SystemException(SOURCE, e);
        }

        int count = getJdbcTemplate().queryForInt("SELECT COUNT(*) FROM dbuserpassword WHERE Domain = ? AND UserId = ?", new Object[] { identity.getDomain(), identity.getUserId() });
        if (count == 0) {
            // New user, without password
            getJdbcTemplate().update("INSERT INTO dbuserpassword VALUES (?, ?, ?)", new Object[] { identity.getDomain(), identity.getUserId(), cryptPW });
        } else {
            getJdbcTemplate().update("UPDATE dbuserpassword SET Password = ? WHERE Domain = ? AND UserId = ?", new Object[] { cryptPW, identity.getDomain(), identity.getUserId() });
        }
        log.debug("Password set for userid:" + identity.getUserId());
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
}
