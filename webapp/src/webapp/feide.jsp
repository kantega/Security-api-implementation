<%@ page import="no.kantega.security.api.impl.feide.identity.FeideIdentityResolver"%>
<%@ page import="no.kantega.security.api.identity.AuthenticatedIdentity"%>
<%@ page import="no.kantega.security.api.profile.Profile"%>
<%@ page import="no.kantega.security.api.impl.feide.profile.FeideProfileManager"%>
<%@ page import="no.kantega.security.api.impl.ldap.role.LdapRoleManager"%>
<%@ page import="java.util.Iterator"%>
<%@ page import="no.kantega.security.api.role.Role"%>
<html>
<body>
<%
    FeideIdentityResolver resolver = new FeideIdentityResolver();
    resolver.setLoginPageUrl("https://sbtest.kantega.no:1443/federation/spssoinit?metaAlias=%2Fsp&amp;idpEntityID=sam.feide.no&amp;AuthnContextClassRef=Password&amp;binding=HTTP-POST&amp;NameIDFormat=transient");
    resolver.setLogoutPageUrl("https://sam.feide.no/amserver/saml2/jsp/idpSingleLogoutInit.jsp?binding=urn:oasis:names:tc:SAML:2.0:bindings:SOAP");
    resolver.setAuthenticationContext("feide");

    AuthenticatedIdentity identity = resolver.getIdentity(request);
    if (identity != null) {
        out.write("Feide userid:" + identity.getUserId() + "<br>");
        FeideProfileManager profileManager = new FeideProfileManager();
        Profile profile = profileManager.getProfileForUser(identity);
        if (profile != null) {
            out.write("Email:" + profile.getEmail() + "<br>");
            out.write("Givenname:" + profile.getGivenName() + "<br>");
            out.write("Surname:" + profile.getSurname() + "<br>");
        }

        LdapRoleManager roleManager = new LdapRoleManager();
        roleManager.setAdminUser("");
        roleManager.setAdminPassword("");
        roleManager.setHost("ldap.uninett.no");
        roleManager.setSearchBaseUsers("ou=people,dc=uninett,dc=no");
        roleManager.setSearchBaseRoles("ou=webaccess,dc=uninett,dc=no");
        roleManager.setDepartmentAttribute("ou");
        roleManager.setDomain("feide");
        roleManager.setObjectClassRoles("posixGroup");
        roleManager.setObjectClassUsers("");
        roleManager.setUsernameAttribute("eduPersonPrincipalName");
        roleManager.setRoleMemberAttribute("memberUid");
        roleManager.setRoleUserKey("uid");
        Iterator it = roleManager.getRolesForUser(identity);

        out.write("Roles:<br><ul>");
        while (it.hasNext()) {
            Role role =  (Role)it.next();
            out.write("<li>" + role.getName() + "</li>");
        }
        out.write("</ul>");
    }
%>
</body>
</html>