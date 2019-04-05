package no.kantega.security.api.impl.ldap.role;

import com.novell.ldap.*;
import no.kantega.security.api.common.SystemException;
import no.kantega.security.api.identity.DefaultIdentity;
import no.kantega.security.api.identity.Identity;
import no.kantega.security.api.impl.ldap.CloseableLdapConnection;
import no.kantega.security.api.impl.ldap.LdapConfigurable;
import no.kantega.security.api.role.*;
import no.kantega.security.api.search.DefaultRoleSearchResult;
import no.kantega.security.api.search.SearchResult;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/**
 *
 * Henter roller fra LDAP ut i fra en organisasjonstankegang, dvs alle organization units blir en rolle
 *
 */
public class LdapOrganizationUnitRoleManager extends LdapConfigurable implements RoleManager {
    private String orgUnitNameAttribute = "ou";
    private String orgUnitKeyAttribute = "distinguishedName";


    private String domain = "";

    public Iterator<Role> getAllRoles() throws SystemException {
        return searchRoles(null).getAllResults();
    }

    public SearchResult<Role> searchRoles(String rolename) throws SystemException {
        DefaultRoleSearchResult searchResult = new DefaultRoleSearchResult();

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

        try (CloseableLdapConnection c = getLdapConnection()){
            c.bind(LDAPConnection.LDAP_V3, adminUser, adminPassword.getBytes());

            LDAPSearchConstraints ldapConstraints = new LDAPSearchConstraints();
            ldapConstraints.setMaxResults(maxSearchResults);
            c.setConstraints(ldapConstraints);

            LDAPSearchResults results = c.search(searchBaseUsers, LDAPConnection.SCOPE_SUB, filter, new String[]{orgUnitKeyAttribute, orgUnitNameAttribute, "objectClass"}, false);
            List<Role> roles = new ArrayList<>(results.getCount());
            while (results.hasMore()) {
                try {
                    roles.add(getRoleFromLDAPEntry(results.next()));
                } catch (LDAPReferralException l) {
                    // Ignore LDAPReferralException
                }
            }

            // Sorter
            Collections.sort(roles, new RoleComparator());
            searchResult.setResults(roles);

        } catch (Exception e) {
             throw new SystemException("Feil ved lesing av LDAP directory", e);
        }
        return searchResult;
    }


    public Role getRoleById(RoleId roleId) throws SystemException {
        Role role = null;

        if (!roleId.getDomain().equals(domain)) {
            return null;
        }

        try (CloseableLdapConnection c = getLdapConnection()){
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

        } catch (LDAPException | IOException e) {
             throw new SystemException("Feil ved lesing av LDAP directory", e);
        }
        return role;

    }


    public Iterator<Role> getRolesForUser(Identity identity) throws SystemException {
        List<Role> roles = new ArrayList<>();
        if (!identity.getDomain().equals(domain)) {
            return roles.iterator();
        }

        String userFilter;
        if (objectClassUsers.length() > 0) {
            userFilter = "(&(objectclass=" + objectClassUsers + ")(" + usernameAttribute + "=" + identity.getUserId() + "))";
        } else {
            userFilter = "(" + usernameAttribute + "=" + identity.getUserId() + ")";
        }


        try (CloseableLdapConnection c = getLdapConnection()){
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
        }
        return roles.iterator();
    }


    public Iterator<Identity> getUsersWithRole(RoleId roleId) throws SystemException {
        List<Identity> users = new ArrayList<>();

        if (!roleId.getDomain().equals(domain)) {
            return users.iterator();
        }

        try (CloseableLdapConnection c = getLdapConnection()){
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
            LDAPSearchResults results = c.search(searchBaseUsers, LDAPConnection.SCOPE_SUB, filter, new String[]{orgUnitKeyAttribute, "objectClass"}, false, constraints);
            if (results.hasMore()) {
                try {
                    LDAPEntry entry = results.next();
                    String dn = entry.getDN();

                    // S�k opp brukere innenfor denne delen av basen
                    LDAPSearchConstraints ldapConstraints = new LDAPSearchConstraints();
                    ldapConstraints.setMaxResults(maxSearchResults);
                    c.setConstraints(ldapConstraints);

                    String[] searchAttributes = new String[] {usernameAttribute};

                    LDAPSearchResults usersResults = c.search(dn, LDAPConnection.SCOPE_SUB, "(objectclass=" + objectClassUsers + ")", searchAttributes, false);
                    while (usersResults.hasMore()) {
                        try {
                            LDAPEntry userEntry = usersResults.next();
                            String userId = getValue(userEntry, usernameAttribute);
                            if (userId != null && !userId.endsWith("$")) {
                                DefaultIdentity identity = new DefaultIdentity();
                                identity.setUserId(userId);
                                identity.setDomain(domain);
                                users.add(identity);
                            }

                        } catch (LDAPReferralException l) {
                            // Ignore LDAPReferralException
                        }
                    }


                } catch (LDAPReferralException l) {
                    // Ignore LDAPReferralException
                }
            }

        } catch (LDAPException | IOException e) {
             throw new SystemException("Feil ved lesing av LDAP directory", e);
        }
        return users.iterator();
    }


    public boolean userHasRole(Identity identity, String roleId) throws SystemException {
        if (!identity.getDomain().equals(domain)) {
            return false;
        }

        Iterator<Role> it = getRolesForUser(identity);
        while (it.hasNext()) {
            Role role = it.next();
            if (role.getId().equalsIgnoreCase(roleId))
                return true;
        }

        return false;
    }


    private Role getRoleFromLDAPEntry(LDAPEntry entry) {
        String roleId = getValue(entry, orgUnitKeyAttribute);
        String roleName = getValue(entry, orgUnitNameAttribute);

        if ("distinguishedName".equalsIgnoreCase(orgUnitKeyAttribute)) {
            String units[] = roleId.split(",");
            int start = 0;
            if (searchBaseUsers.length() > 0) {
                String baseUnits[] = searchBaseUsers.split(",");
                start = baseUnits.length;
            }
            if (units.length > start) {
                roleName += " (";
                for (int i = 0; i < units.length - start; i++) {
                    if (i > 0) {
                        roleName += " / ";
                    }
                    String unit = units[i];
                    unit = unit.substring(unit.indexOf("=") + 1, unit.length());
                    roleName += unit;
                }
                roleName += ")";
            }
        }

        DefaultRole role = new DefaultRole();
        role.setId(roleId);
        role.setName(roleName);
        role.setDomain(domain);
        return role;
    }


    public void setDomain(String domain) {
        this.domain = domain;
    }

}

