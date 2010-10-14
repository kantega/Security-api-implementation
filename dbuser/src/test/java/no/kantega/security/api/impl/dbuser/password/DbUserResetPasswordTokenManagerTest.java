package no.kantega.security.api.impl.dbuser.password;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import org.junit.Test;

import no.kantega.security.api.common.SystemException;
import no.kantega.security.api.identity.DefaultIdentity;
import no.kantega.security.api.impl.dbuser.util.HSQLDBDatabaseCreator;
import no.kantega.security.api.password.ResetPasswordToken;

import javax.sql.DataSource;
import java.util.Date;

public class DbUserResetPasswordTokenManagerTest {
    @Test
    public void testGenerateResetPasswordToken() throws SystemException {
        DbUserResetPasswordTokenManager tokenManager = new DbUserResetPasswordTokenManager();
        DataSource dataSource = new HSQLDBDatabaseCreator("dbuser", getClass().getClassLoader().getResourceAsStream("dbuser.sql")).createDatabase();
        tokenManager.setDataSource(dataSource);

        DefaultIdentity identity = new DefaultIdentity();
        identity.setDomain("domain");
        identity.setUserId("userid");

        ResetPasswordToken token = tokenManager.generateResetPasswordToken(identity, new Date());

        assertNotNull("token not null", token.getToken());

        ResetPasswordToken token2 = tokenManager.generateResetPasswordToken(identity, new Date());
        assertFalse("token1 != token2", token.getToken().equalsIgnoreCase(token2.getToken()));

    }

    @Test
    public void testVerifyPasswordToken() throws SystemException {
        DbUserResetPasswordTokenManager tokenManager = new DbUserResetPasswordTokenManager();
        DataSource dataSource = new HSQLDBDatabaseCreator("dbuser", getClass().getClassLoader().getResourceAsStream("dbuser.sql")).createDatabase();
        tokenManager.setDataSource(dataSource);

        DefaultIdentity identity = new DefaultIdentity();
        identity.setDomain("domain");
        identity.setUserId("userid");

        Date soon = new Date(new Date().getTime() + 1000*60*60);

        ResetPasswordToken token = tokenManager.generateResetPasswordToken(identity, soon);

        assertTrue("valid token", tokenManager.verifyPasswordToken(identity, token));

        Date before = new Date(new Date().getTime() - 1000*60*60);

        token = tokenManager.generateResetPasswordToken(identity, before);

        assertFalse("token expired", tokenManager.verifyPasswordToken(identity, token));

    }

}
