package no.kantega.security.api.impl.ldap.role;

import no.kantega.security.api.impl.ldap.LdapConfigurable;
import no.kantega.security.api.role.*;
import no.kantega.security.api.common.SystemException;
import no.kantega.security.api.search.SearchResult;
import no.kantega.security.api.search.DefaultSearchResult;
import no.kantega.security.api.identity.Identity;
import no.kantega.security.api.identity.DefaultIdentity;

import java.util.Iterator;
import java.util.List;
import java.util.ArrayList;

import com.novell.ldap.*;

/**
 *
 * Henter roller fra LDAP ut i fra en organisasjonstankegang, dvs alle organization units blir en rolle
 *
 */
public class LdapOrganizationUnitRoleManager extends LdapConfigurable implements RoleManager {
    private String orgUnitNameAttribute = "ou";
    private String orgUnitKeyAttribute = "distinguishedName";


    private String domain = "";

    public Iterator getAllRoles() throws SystemException {
        return searchRoles(null).getAllResults();
    }

    public SearchResult searchRoles(String rolename) throws SystemException {
        DefaultSearchResult searchResult = new DefaultSearchResult();
        LDAPConnection c = new LDAPConnection();

        String filter = "";
        if (objectClassOrgUnits.length() > 0 && rolename != null && rolename.length() > 0) {
            filter += "(&";
        }

        if (objectClassOrgUnits.length() > 0) {
            filter += "(objectclass=" + objectClassOrgUnits + ")";
        }

        if (rolename != null) {
            rolename = escapeChars(rolename);
            if (rolename.length() > 0) {
                filter += "(" + orgUnitNameAttribute + "=" + rolename + "*)";
            }
        }

        if (objectClassOrgUnits.length() > 0 && rolename != null && rolename.length() > 0) {
            filter += ")";
        }

        try {
            c.connect(host, port);
            c.bind(LDAPConnection.LDAP_V3, adminUser, adminPassword.getBytes());

            LDAPSearchConstraints ldapConstraints = new LDAPSearchConstraints();
            ldapConstraints.setMaxResults(maxSearchResults);
            c.setConstraints(ldapConstraints);

            LDAPSearchResults results = c.search(searchBaseUsers, LDAPConnection.SCOPE_SUB, filter, new String[]{orgUnitKeyAttribute, orgUnitNameAttribute, "objectClass"}, false);
            while (results.hasMore()) {
                try {
                    searchResult.addResult(getRoleFromLDAPEntry(results.next()));
                } catch (LDAPReferralException l) {
                    // Ignore LDAPReferralException
                }
            }

        } catch (Exception e) {
             throw new SystemException("Feil ved lesing av LDAP directory", e);
        } finally {
            try {
                c.disconnect();
            } catch (LDAPException e) {
                //
            }
        }
        return searchResult;
    }


    public Role getRoleById(RoleId roleId) throws SystemException {
        Role role = null;

        if (!roleId.getDomain().equals(domain)) {
            return null;
        }

        LDAPConnection c = new LDAPConnection();

        try {
            c.connect(host, port);
            c.bind(LDAPConnection.LDAP_V3, adminUser, adminPassword.getBytes());
            LDAPSearchConstraints constraints = new LDAPSearchConstraints();
            constraints.setDereference(LDAPSearchConstraints.DEREF_ALWAYS);
            c.setConstraints(constraints);

            String filter = "(&";
            if (objectClassOrgUnits.length() > 0) {
                filter += "(objectclass=" + objectClassOrgUnits + ")";
            }

            String id = roleId.getId();
            id = escapeChars(id);

            filter += "(" + orgUnitKeyAttribute + "=" + id + ")";

            filter += ")";
            LDAPSearchResults results = c.search(searchBaseUsers, LDAPConnection.SCOPE_SUB, filter, new String[]{orgUnitKeyAttribute, orgUnitNameAttribute, "objectClass"}, false, constraints);
            if (results.hasMore()) {
                try {
                    LDAPEntry entry = results.next();
                    role = getRoleFromLDAPEntry(entry);
                } catch (LDAPReferralException l) {
                    // Ignore LDAPReferralException
                }
            }

        } catch (LDAPException e) {
             throw new SystemException("Feil ved lesing av LDAP directory", e);
        } finally {
            try {
                c.disconnect();
            } catch (LDAPException e) {
                //
            }
        }
        return role;

    }


    public Iterator getRolesForUser(Identity identity) throws SystemException {

        List roles = new ArrayList();

        LDAPConnection c = new LDAPConnection();

        String userFilter = "";
        if (objectClassUsers.length() > 0) {
            userFilter = "(&(objectclass=" + objectClassUsers + ")(" + usernameAttribute + "=" + identity.getUserId() + "))";
        } else {
            userFilter = "(" + usernameAttribute + "=" + identity.getUserId() + ")";
        }


        try {
            c.connect(host, port);
            c.bind(LDAPConnection.LDAP_V3, adminUser, adminPassword.getBytes());

            LDAPSearchResults user = c.search(searchBaseUsers, LDAPConnection.SCOPE_SUB, userFilter, new String[0], false);
            if (user.hasMore()) {
                LDAPEntry userEntry = user.next();

                String dn = userEntry.getDN();
                String[] orgUnits = dn.split(",");

                String orgUnitId = "";
                for (int i = 0; i < orgUnits.length; i++) {
                    if (i == 0) {
                        orgUnitId = orgUnits[orgUnits.length - (i+1)];
                    } else {
                        orgUnitId = orgUnits[orgUnits.length - (i+1)] + "," + orgUnitId;
                    }

                    DefaultRoleId roleId = new DefaultRoleId();
                    roleId.setDomain(domain);
                    roleId.setId(orgUnitId);

                    Role role = getRoleById(roleId);
                    if (role != null) {
                        roles.add(role);
                    }
                }
            }
        } catch (Exception e) {
             throw new SystemException("Feil ved lesing av LDAP directory", e);
        } finally {
            try {
                c.disconnect();
            } catch (LDAPException e) {
                //
            }
        }


        return roles.iterator();
    }


    public boolean userHasRole(Identity identity, String roleId) throws SystemException {
        Iterator it = getRolesForUser(identity);
        while (it.hasNext()) {
            Role role = (Role)it.next();
            if (role.getId().equalsIgnoreCase(roleId))
                return true;
        }

        return false;
    }


    private Role getRoleFromLDAPEntry(LDAPEntry entry) {
        String roleId = getValue(entry, orgUnitKeyAttribute);
        String roleName = getValue(entry, orgUnitNameAttribute);

        DefaultRole role = new DefaultRole();
        role.setId(roleId);
        role.setName(roleName);
        role.setDomain(domain);
        return role;
    }


    public void setDomain(String domain) {
        this.domain = domain;
    }

    public static void main(String[] args) {
        try {
            LdapOrganizationUnitRoleManager manager = new LdapOrganizationUnitRoleManager();
            manager.setAdminUser("ad@mogul.no");
            manager.setAdminPassword("Tzg5hh4Vf");
            manager.setDomain("mogul");
            manager.setHost("tom.mogul.no");
            manager.setSearchBaseUsers("ou=Norway,dc=mogul,dc=no");
            manager.setSearchBaseRoles("ou=Norway,dc=mogul,dc=no");

            DefaultIdentity andska = new DefaultIdentity();
            andska.setUserId("aksess2");
            andska.setDomain("mogul");

            Iterator roles = manager.getRolesForUser(andska);
            while (roles.hasNext()) {
                Role role =  (Role)roles.next();
                System.out.println("Role:" + role.getName());
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

