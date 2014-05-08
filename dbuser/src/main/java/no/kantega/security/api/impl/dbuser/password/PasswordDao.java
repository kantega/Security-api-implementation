package no.kantega.security.api.impl.dbuser.password;

import no.kantega.security.api.identity.Identity;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.jdbc.BadSqlGrammarException;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.support.JdbcDaoSupport;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;

/**
 * User: Sigurd Stendal
 * Date: 07.05.14
 */
public class PasswordDao extends JdbcDaoSupport {


    public void updatePasswordInDatabase(Identity identity, String hashedPassword) {
        int count = getJdbcTemplate().queryForObject("SELECT COUNT(*) FROM dbuserpassword WHERE Domain = ? AND UserId = ?", Integer.class,
                identity.getDomain(), identity.getUserId());
        if (count == 0) {
            // New user, without password
            getJdbcTemplate().update("INSERT INTO dbuserpassword (Domain, UserId, Password) VALUES (?, ?, ?)",
                    identity.getDomain(), identity.getUserId(), hashedPassword);
        } else {
            getJdbcTemplate().update("UPDATE dbuserpassword SET Password = ? WHERE Domain = ? AND UserId = ?",
                    hashedPassword, identity.getDomain(), identity.getUserId());
        }
    }

    public void updateMechFieldInDatabase(Identity identity) {
        boolean supportsMech = getSupportsMech();
        if (supportsMech) {
            getJdbcTemplate().update("UPDATE dbuserpassword SET HashMech = null WHERE Domain = ? AND UserId = ?", identity.getDomain(), identity.getUserId());
        }
    }

    public String readPasswordFromDatabase(Identity identity) {
        try {
            return getJdbcTemplate().queryForObject("SELECT Password FROM dbuserpassword WHERE Domain = ? AND UserId = ?", new Object[]{identity.getDomain(), identity.getUserId()}, String.class);
        } catch (IncorrectResultSizeDataAccessException e) {
            return null;
        }
    }

    public List<String> findUsersWithPasswords(String domain) {
        return getJdbcTemplate().query("SELECT UserId FROM dbuserpassword WHERE Domain = ? AND NOT Password IS NULL", new RowMapper<String>() {
            @Override
            public String mapRow(ResultSet rs, int i) throws SQLException {
                return rs.getString("UserId");
            }
        }, domain);
    }

    public String getPasswordHash(String domain, String userId) {
        return getJdbcTemplate().queryForObject("SELECT Password FROM dbuserpassword WHERE Domain = ? AND UserId = ?", new RowMapper<String>() {
            @Override
            public String mapRow(ResultSet rs, int i) throws SQLException {
                return rs.getString("Password");
            }
        }, domain, userId);
    }

    public void storePasswordHash(String domain, String userId, String hash) {
        String sql;
        if (getSupportsMech()) {
            sql = "UPDATE dbuserpassword SET HashMech = null, Password = ? WHERE Domain = ? AND UserId = ?";
        } else {
            sql = "UPDATE dbuserpassword SET Password = ? WHERE Domain = ? AND UserId = ?";
        }

        getJdbcTemplate().update(
                sql,
                hash,
                domain,
                userId);
    }


    public String getPasswordHashAlgorithm(String domain, String userId) {
        if (getSupportsMech()) {
            return getJdbcTemplate().queryForObject("SELECT HashMech FROM dbuserpassword WHERE Domain = ? AND UserId = ?", new RowMapper<String>() {
                @Override
                public String mapRow(ResultSet rs, int i) throws SQLException {
                    return rs.getString("HashMech");
                }
            }, domain, userId);
        } else {
            return null;
        }
    }

    private boolean getSupportsMech() {
        try {
            getJdbcTemplate().queryForObject("select count(HashMech) from dbuserpassword", Integer.class);
            return true;
        } catch (BadSqlGrammarException e) {
            return false;
        }
    }


}
