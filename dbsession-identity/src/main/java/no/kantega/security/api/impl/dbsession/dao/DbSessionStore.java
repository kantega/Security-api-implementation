package no.kantega.security.api.impl.dbsession.dao;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

import javax.sql.DataSource;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;


public class DbSessionStore extends AbstractSessionStore implements InitializingBean{
    private DataSource dataSource;
    private Logger log = LoggerFactory.getLogger(getClass());
    private boolean createTables;

    public String storeSession( String username) {
        String key = generateKey();
        JdbcTemplate template = new JdbcTemplate(dataSource);
        template.update("insert into dbsession(sessionkey, username) VALUES (?, ?)", new Object[] {key, username});
        return key;
    }

    public no.kantega.security.api.impl.dbsession.dao.Session getSession(String key) {
        JdbcTemplate template = new JdbcTemplate(dataSource);
        List sessions = template.query("select username from dbsession  where sessionkey=?", new String[] {key}, new RowMapper() {
            public Object mapRow(ResultSet set, int i) throws SQLException {
                String username = set.getString("username");
                return new DbSession(username);
            }
        });

        if(sessions.size() == 0) {
            if(log.isDebugEnabled()) {
                log.debug("Found zero sessions, returning null");
            }
            return null;
        } else if(sessions.size() > 1) {
            throw new IllegalStateException("Found multiple sessions for key " + key);
        } else {
            return (no.kantega.security.api.impl.dbsession.dao.Session) sessions.get(0);
        }
    }

    public void removeSession(String key) {
        new JdbcTemplate(dataSource).update("delete from dbsession where sessionkey=?", new String[] {key});
    }

    public void setDataSource(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    public void afterPropertiesSet() throws Exception {
        if(createTables) {
            new JdbcTemplate(dataSource).execute("create table dbsession (sessionkey varchar(255) not null, username varchar(255) not null);");
        }
    }

    public void setCreateTables(boolean createTables) {
        this.createTables = createTables;
    }

    class DbSession implements Session {
        private String username;

        DbSession(String username) {
            this.username = username;
        }

        public String getUsername() {
            return username;
        }
    }
}
