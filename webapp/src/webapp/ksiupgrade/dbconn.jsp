<%@ page import="org.springframework.jdbc.datasource.DriverManagerDataSource" %>
<%@ page import="java.sql.Connection" %>
<%
    String dbKsiDriver = "org.apache.derby.jdbc.EmbeddedDriver";
    String dbKsiUrl = "jdbc:derby:c:/ksi.derby;create=true";
    String dbKsiUsername = "";
    String dbKsiPassword = "";

    DriverManagerDataSource ksiDs = new DriverManagerDataSource();
    ksiDs.setDriverClassName(dbKsiDriver);
    ksiDs.setUrl(dbKsiUrl);
    ksiDs.setUsername(dbKsiUsername);
    ksiDs.setPassword(dbKsiPassword);

    String dbAksessDriver = "net.sourceforge.jtds.jdbc.Driver";
    String dbAksessUrl = "jdbc:jtds:sqlserver://62.92.44.133:3180/dnweb;tds=8.0;loginTimeout=15";
    String dbAksessUsername = "kantega";
    String dbAksessPassword = "stygtpass55";

    DriverManagerDataSource aksessDs = new DriverManagerDataSource();
    aksessDs.setDriverClassName(dbAksessDriver);
    aksessDs.setUrl(dbAksessUrl);
    aksessDs.setUsername(dbAksessUsername);
    aksessDs.setPassword(dbAksessPassword);
%>