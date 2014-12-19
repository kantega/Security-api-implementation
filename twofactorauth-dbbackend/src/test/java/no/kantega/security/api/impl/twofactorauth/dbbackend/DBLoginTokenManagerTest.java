package no.kantega.security.api.impl.twofactorauth.dbbackend;

import no.kantega.security.api.identity.DefaultIdentity;
import no.kantega.security.api.identity.Identity;
import no.kantega.security.api.twofactorauth.DefaultLoginToken;
import no.kantega.security.api.twofactorauth.LoginToken;
import org.apache.commons.dbcp2.BasicDataSource;
import org.apache.ddlutils.Platform;
import org.apache.ddlutils.PlatformFactory;
import org.apache.ddlutils.PlatformUtils;
import org.apache.ddlutils.io.DatabaseIO;
import org.apache.ddlutils.model.Database;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.sql.DataSource;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.SQLException;
import java.util.Date;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;

public class DBLoginTokenManagerTest {

    private DBLoginTokenManager dbLoginTokenManager;

    @Before
    public void setup() throws SQLException, IOException {
        DataSource dataSource = DataSourceCreator.create();

        try(InputStream stream = getClass().getResourceAsStream("/META-INF/resources/WEB-INF/dbmigrate/oa/201412190959/twofactorauth-schema.xml");
            Connection c = dataSource.getConnection()){

            Database model = new DatabaseIO().read(new InputStreamReader(stream, Charset.forName("utf-8")));
            DatabaseMetaData metaData = c.getMetaData();
            Platform platform = PlatformFactory.createNewPlatformInstance(new PlatformUtils().determineDatabaseType(metaData.getDriverName(), metaData.getURL()));
            platform.setSqlCommentsOn(false);
            platform.createModel(c, model, false, false);
        }

        dbLoginTokenManager = new DBLoginTokenManager();
        dbLoginTokenManager.setDataSource(dataSource);
    }

    @Test
    public void generateLoginToken(){
        LoginToken loginToken = dbLoginTokenManager.generateLoginToken(DefaultIdentity.withDomainAndUserId("domain", "userid"));
        assertThat(loginToken, notNullValue());
        assertThat(loginToken.getToken(), notNullValue());
        assertThat(loginToken.getToken().length(), is(5));
    }

    @Test
    public void validLoginToken(){
        Identity identity = DefaultIdentity.withDomainAndUserId("domain", "userid");
        LoginToken loginToken = dbLoginTokenManager.generateLoginToken(identity);

        boolean isValidToken = dbLoginTokenManager.verifyLoginToken(identity, loginToken);
        assertThat("Token should be valid", isValidToken, is(true));
    }

    @Test
    public void nonExistingLoginToken(){
        Identity identity = DefaultIdentity.withDomainAndUserId("domain", "userid");
        boolean isValidToken = dbLoginTokenManager.verifyLoginToken(identity, new DefaultLoginToken("12345"));
        assertThat("Token should be invalid", isValidToken, is(false));
    }

    @Test
    public void ExpiredLoginToken(){
        Identity identity = DefaultIdentity.withDomainAndUserId("domain", "userid");
        LoginToken loginToken = dbLoginTokenManager.generateLoginToken(identity);

        dbLoginTokenManager.getJdbcTemplate().update("update twofactorauthtoken set expiredate = ?", new Date());
        boolean isValidToken = dbLoginTokenManager.verifyLoginToken(identity, loginToken);

        assertThat("Token should be expired", isValidToken, is(false));
    }

    @After
    public void tearDown() throws SQLException {
        BasicDataSource dataSource = (BasicDataSource) dbLoginTokenManager.getDataSource();
        dataSource.close();
    }
}
