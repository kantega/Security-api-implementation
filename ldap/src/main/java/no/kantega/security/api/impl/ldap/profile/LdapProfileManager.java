package no.kantega.security.api.impl.ldap.profile;

import com.novell.ldap.*;
import com.novell.ldap.util.Base64;
import no.kantega.security.api.common.SystemException;
import no.kantega.security.api.identity.DefaultIdentity;
import no.kantega.security.api.identity.Identity;
import no.kantega.security.api.impl.ldap.CloseableLdapConnection;
import no.kantega.security.api.impl.ldap.LdapConfigurable;
import no.kantega.security.api.profile.DefaultProfile;
import no.kantega.security.api.profile.Profile;
import no.kantega.security.api.profile.ProfileComparator;
import no.kantega.security.api.profile.ProfileManager;
import no.kantega.security.api.search.DefaultProfileSearchResult;
import no.kantega.security.api.search.SearchResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

/**
 * Implementation of <code>ProfileManager</code> that get user properties from LDAP.
 */
public class LdapProfileManager extends LdapConfigurable implements ProfileManager {
    private final Logger log = LoggerFactory.getLogger(getClass());
    private String domain = "";

    public SearchResult<Profile> searchProfiles(String name) throws SystemException {
        DefaultProfileSearchResult searchResult = new DefaultProfileSearchResult();

        if (name == null) name = "";

        name = escapeChars(name).trim();

        if (name.length() < 3) {
            return searchResult;
        }

        try (CloseableLdapConnection c = getLdapConnection()){
            c.bind(LDAPConnection.LDAP_V3, adminUser, adminPassword.getBytes());

            String filter = "(&";
            if (objectClassUsers.length() > 0) {
                filter += "(objectclass=" + objectClassUsers + ")";
            }

            if (name.length() > 0) {
                String name1 = name;
                String name2 = "";
                if (name.contains(" ")) {
                    name1 = name.substring(0, name.lastIndexOf(" ")).trim();
                    name2 = name.substring(name.lastIndexOf(" "), name.length()).trim();
                }

                name1 = escapeChars(name1);
                name2 = escapeChars(name2);

                if (name2.length() > 0) {
                    // Search for givenname = name1* and surname = name2*
                    filter += "(" + givenNameAttribute + "=" + name1 + "*)(" + surnameAttribute + "=" + name2 + "*)";
                } else {
                    // Search for givenname = name1* or surname = name1* or username = name1
                    filter += "(|(" + givenNameAttribute + "=" + name1 + "*)(" + surnameAttribute + "=" + name1 + "*)(" + usernameAttribute + "=" + name1 + "))";
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

            log.debug("c.search({}, LDAPConnection.SCOPE_SUB, {}, {}, false)", searchBaseUsers, filter, searchAttributes);
            LDAPSearchResults results = c.search(searchBaseUsers, LDAPConnection.SCOPE_SUB, filter, searchAttributes, false);
            List<Profile> profiles = new ArrayList<>();

            while (results.hasMore()) {
                try {
                    LDAPEntry entry = results.next();
                    log.debug("Got entry {}", entry);
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
        }
        return searchResult;
    }


    public Profile getProfileForUser(Identity identity) throws SystemException {
        if (!identity.getDomain().equals(domain)) {
            return null;
        }

        Profile profile = null;

        final String userId = escapeChars( identity.getUserId() );

        try (CloseableLdapConnection c = getLdapConnection()){
            String filter;
            if (objectClassUsers.length() > 0) {
                filter = "(&(objectclass=" + objectClassUsers + ")(" + usernameAttribute + "=" + userId + "))";
            } else {
                filter = "(" + usernameAttribute + "=" + userId + ")";
            }

            c.bind(LDAPConnection.LDAP_V3, adminUser, adminPassword.getBytes());

            log.debug("c.search({}, LDAPConnection.SCOPE_SUB, {}, new String[0], false)", searchBaseUsers, filter);
            LDAPSearchResults results = c.search(searchBaseUsers, LDAPConnection.SCOPE_SUB, filter, new String[0], false);
            if (results.hasMore()) {
                try {
                    LDAPEntry entry = results.next();
                    log.debug("Got entry {}", entry);
                    // Hent alle attributtene
                    entry = c.read(entry.getDN());

                    profile = getProfileFromLDAPEntry(entry, true);

                    return profile;
                } catch (LDAPReferralException l) {
                    // Ignore LDAPReferralException
                }

            }

        } catch (LDAPException | IOException e) {
             throw new SystemException("Feil ved lesing av LDAP directory for:" + identity.getUserId(), e);
        }
        return profile;
    }

    public SearchResult<Profile> getProfileForUsers(List<Identity> identities) throws SystemException {
        List<Profile> profiles = new ArrayList<>();
        for (Identity identity : identities) {
            Profile profile = getProfileForUser(identity);
            if (profile != null) {
                profiles.add(profile);
            }
        }
        DefaultProfileSearchResult searchResult = new DefaultProfileSearchResult();
        searchResult.setResults(profiles);
        return searchResult;
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

                for (Object o : entry.getAttributeSet()) {
                    LDAPAttribute a = (LDAPAttribute) o;
                    String name = a.getName();
                    String value = "";
                    if ("photo".equalsIgnoreCase(name) || "jpegPhoto".equalsIgnoreCase(name)) {
                        value = Base64.encode(a.getByteValue());
                    } else {
                        value = a.getStringValue();
                    }
                    p.setProperty(a.getName(), value);

                }
                profile.setRawAttributes(p);
            }
        }
        return profile;
    }
}
