<%@ page import="java.sql.Connection" %>
<%@ page import="java.sql.PreparedStatement" %>
<%@ page import="java.sql.ResultSet" %>
<%@ page import="com.novell.ldap.*" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ include file="dbconn.jsp"%>
<%@ include file="ldapconn.jsp"%>
<%
    Connection cKsi = ksiDs.getConnection();
    PreparedStatement ksiSt = cKsi.prepareStatement("select * from user_role");

    Connection cAksess = ksiDs.getConnection();

    PreparedStatement deleteSt = cAksess.prepareStatement("delete from dbuserrole2user");
    deleteSt.executeUpdate();

    PreparedStatement aksessSt = cAksess.prepareStatement("insert into dbuserrole2user values ('dbuser',?, 'ldap', ?)");


    LDAPConnection c = new LDAPConnection();

    c.connect(ldapHost, ldapPort);

    try {
        ResultSet ksiRs = ksiSt.executeQuery();
        while(ksiRs.next()) {
            String userId   = ksiRs.getString("user_profile_id");
            String roleId   = ksiRs.getString("role_id");

            if (userId.indexOf("=") != -1) {

                String str = userId;
                str = str.replaceAll("\\\\", "\\\\\\\\");
                str = str.replaceAll("\\(", "\\\\28");
                str = str.replaceAll("\\)", "\\\\29");
                str = str.replaceAll("\\*", "\\\\*");
                str = str.replaceAll("\\&", "\\\\&");
                str = str.replaceAll("\\!", "\\\\!");


                String realUserId = null;

                LDAPEntry entry = c.read(str);
                if (entry != null) {
                    LDAPAttribute attribute = entry.getAttribute("sAMAccountName");

                    if (attribute != null) {
                        realUserId = attribute.getStringValue();
                    }

                }

                if (realUserId != null) {
                    aksessSt.setString(1, roleId);
                    aksessSt.setString(2, realUserId);
                    %>
                    Konverterer bruker:<%=realUserId%><br>
                    <%
                    aksessSt.executeUpdate();                    
                }



            }

        }
    } finally {
        cKsi.close();
        cAksess.close();
        c.disconnect();
    }
%>