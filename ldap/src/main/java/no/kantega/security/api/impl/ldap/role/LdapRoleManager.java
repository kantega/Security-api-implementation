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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/**
 * Henter roller fra LDAP ut i fra en gruppetankegang, dvs alle grupper (groups) blir en rolle
 */
public class LdapRoleManager extends LdapConfigurable implements RoleManager {
    private final Logger log = LoggerFactory.getLogger(getClass());
    private String domain = "";

    public Iterator<Role> getAllRoles() throws SystemException {
        return searchRoles(null).getAllResults();
    }

    public SearchResult<Role> searchRoles(String rolename) throws SystemException {
        DefaultRoleSearchResult searchResult = new DefaultRoleSearchResult();

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

        try (CloseableLdapConnection c = getLdapConnection()){
            c.bind(LDAPConnection.LDAP_V3, adminUser, adminPassword.getBytes());

            LDAPSearchConstraints ldapConstraints = new LDAPSearchConstraints();
            ldapConstraints.setMaxResults(maxSearchResults);
            c.setConstraints(ldapConstraints);
            log.debug("c.search({}, LDAPConnection.SCOPE_SUB, {}, new String[]{{}, \"member\", \"objectClass\"}, false);", searchBaseAllRoles, filter, roleAttribute);
            LDAPSearchResults results = c.search(searchBaseRoles, LDAPConnection.SCOPE_SUB, filter, new String[]{roleAttribute, "member", "objectClass"}, false);
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
            log.debug("c.search({}, LDAPConnection.SCOPE_SUB, {}, new String[]{{}, \"member\", \"objectClass\"}, false, {})", base, filter, roleAttribute, constraints);
            LDAPSearchResults results = c.search(base, LDAPConnection.SCOPE_SUB, filter, new String[]{roleAttribute, "member", "objectClass"}, false, constraints);
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
            log.debug("c.search({}, LDAPConnection.SCOPE_SUB, {}, new String[0], false)", searchBaseUsers, userFilter);
            LDAPSearchResults user = c.search(searchBaseUsers, LDAPConnection.SCOPE_SUB, userFilter, new String[0], false);
            if (user.hasMore()) {
                LDAPEntry userEntry = user.next();
                log.debug("Found entry {}", userEntry);
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

                List<String> rolesDN = new ArrayList<String>();

                // Finn roller som brukeren er gitt direkte tilgang til
                String base = searchBaseAllRoles;
                if (base == null || base.length() == 0) {
                    base = searchBaseRoles;
                }

                LDAPSearchResults resultsRoles = c.search(base, LDAPConnection.SCOPE_SUB, rolesFilter, new String[]{roleAttribute, roleMemberAttribute, "objectClass"}, false);
                while (resultsRoles.hasMore()) {
                    try {
                        LDAPEntry entry = resultsRoles.next();
                        log.debug("Found entry {}", entry);
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
                        String dn = rolesDN.get(i);
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

                    log.debug("c.search({}, LDAPConnection.SCOPE_SUB, {}, new String[]{{}, {}, \"objectClass\"}, false)", base, roleRoleFilter, roleAttribute, roleMemberAttribute);
                    LDAPSearchResults resultsRoleRoles = c.search(base, LDAPConnection.SCOPE_SUB, roleRoleFilter, new String[]{roleAttribute, roleMemberAttribute, "objectClass"}, false);
                    while (resultsRoleRoles.hasMore()) {
                        try {
                            LDAPEntry entry = resultsRoleRoles.next();
                            log.debug("Found entry {}", entry);
                            Role role = getRoleFromLDAPEntry(entry);
                            boolean userHasRole = false;
                            for (Role tmp : roles) {
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
                filter += "(objectclass=" + objectClassRoles + ")";
            }

            String id = roleId.getId();
            id = escapeChars(id);

            filter += "(" + roleAttribute + "=" + id + ")";

            filter += ")";
            log.debug("c.search({}, LDAPConnection.SCOPE_SUB, {}, new String[]{{}, \"objectClass\"}, false, {})", searchBaseUsers, filter, roleAttribute, constraints);
            LDAPSearchResults results = c.search(searchBaseUsers, LDAPConnection.SCOPE_SUB, filter, new String[]{roleAttribute, "objectClass"}, false, constraints);
            if (results.hasMore()) {
                try {
                    LDAPEntry entry = results.next();
                    log.debug("Found entry {}", entry);
                    String roleDN = entry.getDN();

                    // S�k opp brukere innenfor denne delen av basen
                    LDAPSearchConstraints ldapConstraints = new LDAPSearchConstraints();
                    ldapConstraints.setMaxResults(maxSearchResults);
                    c.setConstraints(ldapConstraints);

                    String usersFilter = "(&(objectclass=" + objectClassUsers + ")(" + roleMemberOfAttribute + "=" + roleDN + "))";
                    String[] searchAttributes = new String[] {usernameAttribute};

                    log.debug("c.search({}, LDAPConnection.SCOPE_SUB, {}, {}, false)", searchBaseUsers, users, searchAttributes);
                    LDAPSearchResults usersResults = c.search(searchBaseUsers, LDAPConnection.SCOPE_SUB, usersFilter, searchAttributes, false);
                    while (usersResults.hasMore()) {
                        try {
                            LDAPEntry userEntry = usersResults.next();
                            log.debug("Found entry {}", userEntry);
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

        Iterator it = getRolesForUser(identity);
        while (it.hasNext()) {
            Role role = (Role)it.next();
            if (role.getId().equalsIgnoreCase(roleId))
                return true;
        }

        return false;
    }


    private Role getRoleFromLDAPEntry(LDAPEntry entry) {
        log.debug("Found entry: {}", entry);
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

}
