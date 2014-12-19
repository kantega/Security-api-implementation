package no.kantega.security.api.impl.twofactorauth.dbbackend;

import no.kantega.security.api.identity.Identity;
import no.kantega.security.api.twofactorauth.DefaultLoginToken;
import no.kantega.security.api.twofactorauth.LoginToken;
import no.kantega.security.api.twofactorauth.LoginTokenManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.jdbc.core.support.JdbcDaoSupport;

import java.security.SecureRandom;
import java.util.Calendar;
import java.util.Date;

public class DBLoginTokenManager extends JdbcDaoSupport implements LoginTokenManager {

    private final Logger log = LoggerFactory.getLogger(getClass());

    /**
     * Number of minutes a <code>LoginToken</code> is valid.
     */
    private int tokenValidityMinutes = 5;

    /**
     * Number of digits in <code>LoginToken</code>.
     */
    private int tokenLength = 5;

    private SecureRandom random = new SecureRandom();

    @Override
    public LoginToken generateLoginToken(Identity identity) {
        log.info("Generating LoginToken for " + identity.getDomain() + ":" + identity.getUserId());
        // Delete old tokens for identity
        deleteLoginTokensForIdentity(identity);

        // Generate and save new token
        LoginToken token = createToken();
        getJdbcTemplate().update("insert into twofactorauthtoken (domain, userid, token, expiredate)  values(?,?,?,?)",
                identity.getDomain(), identity.getUserId(), token.getToken(), tokenExpireDate());
        return token;
    }


    @Override
    public void deleteLoginTokensForIdentity(Identity identity) {
        getJdbcTemplate().update("delete from twofactorauthtoken where domain = ? and userid = ?",
                identity.getDomain(), identity.getUserId());
    }

    @Override
    public boolean verifyLoginToken(Identity identity, LoginToken loginToken) {
        log.info("Verifying LoginToken for " + identity.getDomain() + ":" + identity.getUserId());
        boolean tokenIsValid = false;
        try {
            Date expireDate = getJdbcTemplate().queryForObject("select expiredate from twofactorauthtoken where domain=? and userid=? and token=?", Date.class,
                    identity.getDomain(), identity.getUserId(), loginToken.getToken());
            tokenIsValid = expireDate.after(new Date());
            deleteLoginTokensForIdentity(identity);
        } catch (IncorrectResultSizeDataAccessException e) {
            log.info(identity.getDomain() + ":" + identity.getUserId() + " entered unknown token");
        }

        return tokenIsValid;
    }

    private LoginToken createToken() {
        StringBuilder token = new StringBuilder();
        for(int i = 0; i < tokenLength; i++){
            token.append(random.nextInt(10));
        }
        return new DefaultLoginToken(token.toString());
    }

    private Date tokenExpireDate() {
        Calendar expireTime = Calendar.getInstance();
        expireTime.add(Calendar.MINUTE, tokenValidityMinutes);
        return expireTime.getTime();
    }

    public void setTokenValidityMinutes(int tokenValidityMinutes) {
        this.tokenValidityMinutes = tokenValidityMinutes;
    }
}
