package no.kantega.security.api.impl.dbsession.dao;

import junit.framework.TestCase;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;


public class DbSessionStoreTest extends TestCase {
    private DriverManagerDataSource dataSource;
    private DbSessionStore dbSessionStore;

    protected void setUp() throws Exception {
        dataSource  = new DriverManagerDataSource("org.hsqldb.jdbcDriver", "jdbc:hsqldb:mem:aname", "sa", "");
        new JdbcTemplate(dataSource).execute("create table dbsession (sessionkey varchar(255) not null, username varchar(255) not null);");
        dbSessionStore = new DbSessionStore();
        dbSessionStore.setDataSource(dataSource);
    }

    public void testSessionStore() {
        Session session = dbSessionStore.getSession("humhum");
        assertNull(session);


        String username = "eirik";

        String key = dbSessionStore.storeSession(username);

        Session retrievedSession = dbSessionStore.getSession(key);
        assertNotNull(retrievedSession);
        assertEquals(username, retrievedSession.getUsername());

        dbSessionStore.removeSession(key);
        assertNull(dbSessionStore.getSession(key));

    }


}
