package no.kantega.security.api.impl.ldap.profile;

import no.kantega.security.api.profile.ProfileManager;
import no.kantega.security.api.profile.Profile;
import no.kantega.security.api.profile.DefaultProfile;
import no.kantega.security.api.profile.ProfileComparator;
import no.kantega.security.api.search.SearchResult;
import no.kantega.security.api.search.DefaultSearchResult;
import no.kantega.security.api.identity.Identity;
import no.kantega.security.api.identity.DefaultIdentity;
import no.kantega.security.api.impl.ldap.LdapConfigurable;
import no.kantega.security.api.common.SystemException;
import com.novell.ldap.*;

import java.util.*;

/**
 * Created by IntelliJ IDEA.
 * User: andersskar
 * Date: Jan 10, 2007
 * Time: 12:37:29 PM
 * To change this template use File | Settings | File Templates.
 */
public class LdapProfileManager extends LdapConfigurable implements ProfileManager {
    private String domain = "";

    public SearchResult searchProfiles(String name) throws SystemException {
        DefaultSearchResult searchResult = new DefaultSearchResult();

        if (name == null) name = "";

        name = escapeChars(name).trim();

        if (name.length() < 3) {
            return searchResult;
        }

        LDAPConnection c = new LDAPConnection();

        try {
            c.connect(host, port);
            c.bind(LDAPConnection.LDAP_V3, adminUser, adminPassword.getBytes());

            String filter = "(&";
            if (objectClassUsers.length() > 0) {
                filter += "(objectclass=" + objectClassUsers + ")";
            }

            if (name.length() > 0) {
                String name1 = name;
                String name2 = "";
                if (name.indexOf(" ") != -1) {
                    name1 = name.substring(0, name.lastIndexOf(" ")).trim();
                    name2 = name.substring(name.lastIndexOf(" "), name.length()).trim();
                }

                name1 = escapeChars(name1);
                name2 = escapeChars(name2);

                if (name2.length() > 0) {
                    filter += "(" + givenNameAttribute + "=" + name1 + "*)(" + surnameAttribute + "=" + name2 + "*)";
                } else {
                    filter += "(|(" + givenNameAttribute + "=" + name1 + "*)(" + surnameAttribute + "=" + name1 + "*))";
                }
            }

            filter += ")";

            String[] searchAttributes;
            if (departmentAttribute.length() > 0) {
                searchAttributes = new String[] {usernameAttribute,  givenNameAttribute, surnameAttribute, emailAttribute, departmentAttribute};
            } else {
                searchAttributes = new String[] {usernameAttribute,  givenNameAttribute, surnameAttribute, emailAttribute};
            }
            LDAPSearchConstraints ldapConstraints = new LDAPSearchConstraints();
            ldapConstraints.setMaxResults(maxSearchResults);
            c.setConstraints(ldapConstraints);
            LDAPSearchResults results = c.search(searchBaseUsers, LDAPConnection.SCOPE_SUB, filter, searchAttributes, false);
            List profiles = new ArrayList();

            while (results.hasMore()) {
                try {
                    LDAPEntry entry = results.next();
                    Profile profile = getProfileFromLDAPEntry(entry, false);
                    if (profile != null) {
                        profiles.add(profile);
                    }
                } catch (LDAPReferralException l) {
                    // Ignore LDAPReferralException
                }
            }

            Collections.sort(profiles, new ProfileComparator());
            searchResult.setResults(profiles);

        } catch (Exception e) {
            throw new SystemException("Feil ved lesing av LDAP directory", e);
        } finally {
            try {
                c.disconnect();
            } catch (LDAPException e) {
                // Ingenting
            }
        }
        return searchResult;
    }


    public Profile getProfileForUser(Identity identity) throws SystemException {
        if (!identity.getDomain().equals(domain)) {
            return null;
        }

        Profile profile = null;

        LDAPConnection c = new LDAPConnection();

        try {
            c.connect(host, port);
            String filter;
            if (objectClassUsers.length() > 0) {
                filter = "(&(objectclass=" + objectClassUsers + ")(" + usernameAttribute + "=" + identity.getUserId() + "))";
            } else {
                filter = "(" + usernameAttribute + "=" + identity.getUserId() + ")";
            }

            c.bind(LDAPConnection.LDAP_V3, adminUser, adminPassword.getBytes());
            LDAPSearchResults results = c.search(searchBaseUsers, LDAPConnection.SCOPE_SUB, filter, new String[0], false);
            if (results.hasMore()) {
                try {
                    LDAPEntry entry = results.next();

                    // Hent alle attributtene
                    entry = c.read(entry.getDN());

                    profile = getProfileFromLDAPEntry(entry, true);

                    return profile;
                } catch (LDAPReferralException l) {
                    // Ignore LDAPReferralException
                }

            }

        } catch (LDAPException e) {
             throw new SystemException("Feil ved lesing av LDAP directory for:" + identity.getUserId(), e);
        } finally {
            try {
                c.disconnect();
            } catch (LDAPException e) {
                //
            }
        }
        return profile;
    }

    public boolean userHasProfile(Identity identity) throws SystemException {
        return getProfileForUser(identity) != null;
    }


    public void setDomain(String domain) {
        this.domain = domain;
    }

    private Profile getProfileFromLDAPEntry(LDAPEntry entry, boolean getRawAttributes) {
        DefaultProfile profile = null;

        String userId = getValue(entry, usernameAttribute);
        String givenName = getValue(entry, givenNameAttribute);
        String surname = getValue(entry, surnameAttribute);

        if (userId.length() > 0 && (givenName.length() > 0 || surname.length() > 0)) {
            profile = new DefaultProfile();
            DefaultIdentity identity = new DefaultIdentity();
            identity.setUserId(userId);
            identity.setDomain(domain);
            profile.setIdentity(identity);
            profile.setGivenName(givenName);
            profile.setSurname(surname);
            profile.setEmail(getValue(entry, emailAttribute));
            if (departmentAttribute.length() > 0) {
                profile.setDepartment(getValue(entry, departmentAttribute));
            }
            if (getRawAttributes) {
                Properties p = new Properties();

                Iterator i = entry.getAttributeSet().iterator();
                while (i.hasNext()) {
                    LDAPAttribute a = (LDAPAttribute) i.next();
                    p.setProperty(a.getName(), a.getStringValue());
                }
                profile.setRawAttributes(p);
            }
        }
        return profile;
    }

    public static void main(String[] args) {
        try {
            LdapProfileManager manager = new LdapProfileManager();
            manager.setAdminUser("");
            manager.setAdminPassword("");
            manager.setDomain("mogul");
            manager.setHost("ldap.uninett.no");
            manager.setSearchBaseUsers("dc=uninett,dc=no");
            manager.setSearchBaseRoles("dc=uninett,dc=no");
            manager.setUsernameAttribute("uid");

            manager.setObjectClassUsers("person");
            manager.setDepartmentAttribute("ou");

            SearchResult result = manager.searchProfiles("Ingrid");
            System.out.println("Found " + result.getSize() + " userprofiles");
            Iterator profiles = result.getAllResults();

            int count = 1;
            while (profiles.hasNext()) {
                Profile profile =  (Profile)profiles.next();
                System.out.println(count + ": Name:" + profile.getGivenName() + " " + profile.getSurname() + "(" + profile.getEmail() + ")");
                count++;
            }

            /*
            DefaultIdentity andska = new DefaultIdentity();
            andska.setUserId("andska");
            andska.setDomain("mogul");

            Profile profile = manager.getProfileForUser(andska);
            if (profile != null) {
                System.out.println("Found userprofile:" + profile.getGivenName() + " " + profile.getSurname() + " - " + profile.getDepartment());
            }*/
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
