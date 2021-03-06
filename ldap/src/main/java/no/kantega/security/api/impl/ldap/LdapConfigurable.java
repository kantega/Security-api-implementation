package no.kantega.security.api.impl.ldap;

import com.novell.ldap.*;

/**
 * Base class for LDAP searches
 */
public class LdapConfigurable {
    protected static final String ROLE_USER_KEY_DN = "dn";
    protected static final String ROLE_USER_KEY_UID = "uid";

    protected String host = "";
    protected int port = 389;
    protected boolean tls = false;
    protected int maxSearchResults = 1000;
    protected String adminUser = "";
    protected String adminPassword = "";

    protected String objectClassUsers = "user";
    protected String searchBaseUsers = "";

    protected String objectClassRoles = "group";
    protected String searchBaseRoles = "";
    protected String searchBaseAllRoles = "";

    protected String objectClassOrgUnits = "organizationalUnit";

    protected String usernameAttribute = "sAMAccountName";
    protected String givenNameAttribute = "givenName";
    protected String surnameAttribute = "sn";
    protected String departmentAttribute = "department";
    protected String emailAttribute = "mail";

    protected String roleAttribute = "cn";
    protected String roleMemberAttribute = "member";
    protected String roleMemberOfAttribute = "memberOf";

    protected String roleUserKey = ROLE_USER_KEY_DN;

    protected String getValue(LDAPEntry entry, String parameter) {
        LDAPAttribute attribute = entry.getAttribute(parameter);
        if (attribute == null || attribute.getStringValue() == null) {
            return "";
        }
        return attribute.getStringValue();
    }

    protected CloseableLdapConnection getLdapConnection() throws LDAPException {
        CloseableLdapConnection c = tls ?
                new CloseableLdapConnection(new LDAPJSSESecureSocketFactory()) :
                new CloseableLdapConnection();

        c.connect(host, port);
        return c;
    }

    /**
     * Replace and escape strings that will give problem in search
     * @param str
     * @return - string with escaped/replaced chars
     */
    protected String escapeChars(String str) {
        str = str.replaceAll("\\\\", "\\\\\\\\");
        str = str.replaceAll("\\(", "\\\\28");
        str = str.replaceAll("\\)", "\\\\29");
        str = str.replaceAll("\\*", "\\\\*");
        return str;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public void setTls(boolean tls) {
        this.tls = tls;
    }

    public void setMaxSearchResults(int maxSearchResults) {
        this.maxSearchResults = maxSearchResults;
    }

    public void setAdminUser(String adminUser) {
        this.adminUser = adminUser;
    }

    public void setAdminPassword(String adminPassword) {
        this.adminPassword = adminPassword;
    }

    public void setObjectClassUsers(String objectClassUsers) {
        this.objectClassUsers = objectClassUsers;
    }

    public void setSearchBaseUsers(String searchBaseUsers) {
        this.searchBaseUsers = searchBaseUsers;
    }

    public void setObjectClassRoles(String objectClassRoles) {
        this.objectClassRoles = objectClassRoles;
    }

    public void setSearchBaseAllRoles(String searchBaseAllRoles) {
        this.searchBaseAllRoles = searchBaseAllRoles;
    }

    public void setSearchBaseRoles(String searchBaseRoles) {
        this.searchBaseRoles = searchBaseRoles;
    }

    public void setUsernameAttribute(String usernameAttribute) {
        this.usernameAttribute = usernameAttribute;
    }

    public void setGivenNameAttribute(String givenNameAttribute) {
        this.givenNameAttribute = givenNameAttribute;
    }

    public void setSurnameAttribute(String surnameAttribute) {
        this.surnameAttribute = surnameAttribute;
    }

    public void setDepartmentAttribute(String departmentAttribute) {
        this.departmentAttribute = departmentAttribute;
    }

    public void setEmailAttribute(String emailAttribute) {
        this.emailAttribute = emailAttribute;
    }

    public void setRoleAttribute(String roleAttribute) {
        this.roleAttribute = roleAttribute;
    }

    public void setRoleMemberAttribute(String roleMemberAttribute) {
        this.roleMemberAttribute = roleMemberAttribute;
    }

    public void setRoleMemberOfAttribute(String roleMemberOfAttribute) {
        this.roleMemberOfAttribute = roleMemberOfAttribute;
    }

    public void setRoleUserKey(String roleUserKey) {
        this.roleUserKey = roleUserKey;
    }
}
