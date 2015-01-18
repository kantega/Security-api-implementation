package no.kantega.security.api.impl.dbuser.password;

import no.kantega.security.api.common.SystemException;
import no.kantega.security.api.identity.Identity;
import no.kantega.security.api.password.DefaultResetPasswordToken;
import no.kantega.security.api.password.ResetPasswordToken;
import no.kantega.security.api.password.ResetPasswordTokenManager;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.jdbc.core.support.JdbcDaoSupport;

import java.util.Date;
import java.util.UUID;


public class DbUserResetPasswordTokenManager extends JdbcDaoSupport implements ResetPasswordTokenManager {
    @Override
    public ResetPasswordToken generateResetPasswordToken(Identity identity, Date tokenExpireDate) throws SystemException {
        // Delete old tokens for identity
        deleteTokensForIdentity(identity);

        // Generate and save new token
        ResetPasswordToken token = createToken();
        getJdbcTemplate().update("insert into dbuserpasswordresettoken (domain, userid, token, expiredate)  values(?,?,?,?)",
                identity.getDomain(), identity.getUserId(), token.getToken(), tokenExpireDate);
        return token;
    }

    @Override
    public void deleteTokensForIdentity(Identity identity) {
        // Delete old requests for user if any
        getJdbcTemplate().update("delete from dbuserpasswordresettoken where domain = ? and userid = ?",
                identity.getDomain(), identity.getUserId());
    }

    private ResetPasswordToken createToken() {
        DefaultResetPasswordToken token = new DefaultResetPasswordToken();
        token.setToken(UUID.randomUUID().toString());
        return token;
    }

    @Override
    public boolean verifyPasswordToken(Identity identity, ResetPasswordToken token) throws SystemException {
        try {
            Date expireDate = getJdbcTemplate().queryForObject("select expiredate from dbuserpasswordresettoken where domain=? and userid=? and token=?", Date.class,
                    identity.getDomain(), identity.getUserId(), token.getToken());
            if (expireDate.getTime() < new Date().getTime()) {
                // Token has expired, delete
                deleteTokensForIdentity(identity);
                return false;
            }
        } catch (IncorrectResultSizeDataAccessException e) {
            // Token not found
            return false;
        }

        return true;
    }
}
