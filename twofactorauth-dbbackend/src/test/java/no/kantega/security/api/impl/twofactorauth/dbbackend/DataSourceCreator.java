package no.kantega.security.api.impl.twofactorauth.dbbackend;

import org.apache.commons.dbcp2.BasicDataSource;

import javax.sql.DataSource;

public class DataSourceCreator {
    private static int counter;

    public static DataSource create() {
        BasicDataSource dataSource = new BasicDataSource();
        dataSource.setUrl("jdbc:derby:memory:db_" + counter++ + ";create=true");
        dataSource.setDriverClassName("org.apache.derby.jdbc.EmbeddedDriver");
        return dataSource;
    }
}
