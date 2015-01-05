/*
 * Copyright 2014 Kantega AS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package no.kantega.security.api.impl.twofactorauth.dbbackend;

import no.kantega.security.api.identity.Identity;
import no.kantega.security.api.twofactorauth.DefaultLoginToken;
import no.kantega.security.api.twofactorauth.LoginToken;
import no.kantega.security.api.twofactorauth.LoginTokenManager;
import no.kantega.security.api.twofactorauth.LoginTokenVerification;
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
    public LoginTokenVerification verifyLoginToken(Identity identity, LoginToken loginToken) {
        log.info("Verifying LoginToken for " + identity.getDomain() + ":" + identity.getUserId());
        LoginTokenVerification tokenIsValid = LoginTokenVerification.INVALID;
        try {
            Date expireDate = getJdbcTemplate().queryForObject("select expiredate from twofactorauthtoken where domain=? and userid=? and token=?", Date.class,
                    identity.getDomain(), identity.getUserId(), loginToken.getToken());
            boolean tokenIsExpired = expireDate.before(new Date());
            if (tokenIsExpired){
                log.info("LoginToken for " + identity.getDomain() + ":" + identity.getUserId() + " was expired");
                tokenIsValid = LoginTokenVerification.EXPIRED;
            } else {
                tokenIsValid = LoginTokenVerification.VALID;
            }
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
