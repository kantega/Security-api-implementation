<%@ page import="java.sql.Connection" %>
<%@ page import="java.sql.PreparedStatement" %>
<%@ page import="java.sql.ResultSet" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ include file="dbconn.jsp"%>
<%
    Connection cKsi = ksiDs.getConnection();
    PreparedStatement ksiSt = cKsi.prepareStatement("select * from role");

    Connection cAksess = ksiDs.getConnection();

    PreparedStatement deleteSt = cAksess.prepareStatement("delete from dbuserrole");
    deleteSt.executeUpdate();
    
    PreparedStatement aksessSt = cAksess.prepareStatement("insert into dbuserrole values ('dbuser',?,?)");

    try {
        ResultSet ksiRs = ksiSt.executeQuery();
        while(ksiRs.next()) {
            String roleId   = ksiRs.getString("role_id");
            String roleName = ksiRs.getString("role_name");

            aksessSt.setString(1, roleId);
            aksessSt.setString(2, roleName);
%>
            Konverterer rolle:<%=roleName%><br>
<%
            aksessSt.executeUpdate();

        }
    } finally {
        cKsi.close();
        cAksess.close();
    }
%>