package no.kantega.security.api.impl.ldap.role;

import no.kantega.security.api.role.RoleManager;
import no.kantega.security.api.role.Role;
import no.kantega.security.api.role.RoleId;
import no.kantega.security.api.role.DefaultRole;
import no.kantega.security.api.search.SearchResult;
import no.kantega.security.api.search.DefaultSearchResult;
import no.kantega.security.api.identity.Identity;
import no.kantega.security.api.identity.DefaultIdentity;
import no.kantega.security.api.impl.ldap.LdapConfigurable;
import no.kantega.security.api.common.SystemException;

import java.util.Iterator;
import java.util.List;
import java.util.ArrayList;

import com.novell.ldap.*;

/**
 * Henter roller fra LDAP ut i fra en grupppetankegang, dvs alle grupper (groups) blir en rolle
 */
public class LdapRoleManager extends LdapConfigurable implements RoleManager {
    private String domain = "";

    public Iterator getAllRoles() throws SystemException {
        return searchRoles(null).getAllResults();
    }

    public SearchResult searchRoles(String rolename) throws SystemException {
        DefaultSearchResult searchResult = new DefaultSearchResult();
        LDAPConnection c = new LDAPConnection();

        String filter = "";
        if (objectClassRoles.length() > 0 && rolename != null && rolename.length() > 0) {
            filter += "(&";    
        }

        if (objectClassRoles.length() > 0) {
            filter += "(objectclass=" + objectClassRoles + ")";
        }

        if (rolename != null) {
            rolename = escapeChars(rolename);
            if (rolename.length() > 0) {
                filter += "(" + roleAttribute + "=" + rolename + "*)";
            }
        }

        if (objectClassRoles.length() > 0 && rolename != null && rolename.length() > 0) {
            filter += ")";
        }

        try {
            c.connect(host, port);
            c.bind(LDAPConnection.LDAP_V3, adminUser, adminPassword.getBytes());

            LDAPSearchConstraints ldapConstraints = new LDAPSearchConstraints();
            ldapConstraints.setMaxResults(maxSearchResults);
            c.setConstraints(ldapConstraints);

            LDAPSearchResults results = c.search(searchBaseRoles, LDAPConnection.SCOPE_SUB, filter, new String[]{roleAttribute, "member", "objectClass"}, false);
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
            if (objectClassRoles.length() > 0) {
                filter += "(objectclass=" + objectClassRoles + ")";
            }

            String id = roleId.getId();
            id = escapeChars(id);                    

            filter += "(" + roleAttribute + "=" + id + ")";

            filter += ")";

            String base = searchBaseAllRoles;
            if (base == null || base.length() == 0) {
                base = searchBaseRoles;
            }

            LDAPSearchResults results = c.search(base, LDAPConnection.SCOPE_SUB, filter, new String[]{roleAttribute, "member", "objectClass"}, false, constraints);
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
        if (!identity.getDomain().equals(domain)) {
            return roles.iterator();
        }

        LDAPConnection c = new LDAPConnection();

        String userFilter;
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

                String key;
                if (roleUserKey.equalsIgnoreCase(ROLE_USER_KEY_DN)) {
                    key = userEntry.getDN();
                } else {
                    key = getValue(userEntry, roleUserKey);
                }

                key = escapeChars(key);

                String rolesFilter;
                if (objectClassRoles.length() > 0) {
                    rolesFilter = "(&(objectclass=" + objectClassRoles + ")(" + roleMemberAttribute + "=" + key + "))";
                } else {
                    rolesFilter = "(" + roleMemberAttribute + "=" + key + ")";
                }

                List rolesDN = new ArrayList();

                // Finn roller som brukeren er gitt direkte tilgang til
                String base = searchBaseAllRoles;
                if (base == null || base.length() == 0) {
                    base = searchBaseRoles;
                }

                LDAPSearchResults resultsRoles = c.search(base, LDAPConnection.SCOPE_SUB, rolesFilter, new String[]{roleAttribute, roleMemberAttribute, "objectClass"}, false);
                while (resultsRoles.hasMore()) {
                    try {
                        LDAPEntry entry = resultsRoles.next();
                        rolesDN.add(entry.getDN());
                        Role role = getRoleFromLDAPEntry(entry);
                        roles.add(role);

                        // Find roles contained in role
                    } catch (LDAPReferralException l) {
                        // Ignore LDAPReferralException
                    }
                }

                // Finn roller i roller
                if (rolesDN.size() > 0) {
                    String roleRoleFilter = "(&";
                    if (objectClassRoles.length() > 0) {
                        roleRoleFilter += "(objectclass=" + objectClassRoles + ")";
                    }

                    for (int i = 0; i < rolesDN.size(); i++) {
                        String dn = (String) rolesDN.get(i);
                        if (rolesDN.size() > 1 && i == 0) {
                            roleRoleFilter += "(|";
                        }

                        dn = escapeChars(dn);

                        roleRoleFilter += "(" + roleMemberAttribute + "=" + dn + ")";
                        if (rolesDN.size() > 1 && i == rolesDN.size() - 1) {
                            roleRoleFilter += ")";
                        }
                    }

                    roleRoleFilter += ")";

                    LDAPSearchResults resultsRoleRoles = c.search(base, LDAPConnection.SCOPE_SUB, roleRoleFilter, new String[]{roleAttribute, roleMemberAttribute, "objectClass"}, false);
                    while (resultsRoleRoles.hasMore()) {
                        try {
                            LDAPEntry entry = resultsRoleRoles.next();
                            Role role = getRoleFromLDAPEntry(entry);
                            boolean userHasRole = false;
                            for (int i = 0; i < roles.size(); i++) {
                                Role tmp = (Role)roles.get(i);
                                if (role.getId().equals(tmp.getId())) {
                                    userHasRole = true;
                                    break;
                                }
                            }

                            if (!userHasRole) {
                                // Bruker har ikke rolle, legg til den
                                roles.add(role);
                            }
                        } catch (LDAPReferralException l) {
                            // Ignore LDAPReferralException
                        }
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
        if (!identity.getDomain().equals(domain)) {
            return false;
        }

        Iterator it = getRolesForUser(identity);
        while (it.hasNext()) {
            Role role = (Role)it.next();
            if (role.getId().equalsIgnoreCase(roleId))
                return true;
        }

        return false;
    }


    private Role getRoleFromLDAPEntry(LDAPEntry entry) {
        String roleId = getValue(entry, roleAttribute);

        DefaultRole role = new DefaultRole();
        role.setId(roleId);
        role.setName(roleId);
        role.setDomain(domain);
        return role;
    }


    public void setDomain(String domain) {
        this.domain = domain;
    }

    public static void main(String[] args) {
        try {

            LdapRoleManager manager = new LdapRoleManager();
            manager.setAdminUser("ad@mogul.no");
            manager.setAdminPassword("Tzg5hh4Vf");
            manager.setDomain("mogul");
            manager.setHost("tom.mogul.no");
            manager.setSearchBaseUsers("ou=Norway,dc=mogul,dc=no");
            manager.setSearchBaseRoles("ou=Norway,dc=mogul,dc=no");

            DefaultIdentity andska = new DefaultIdentity();
            andska.setUserId("aksess1");
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
