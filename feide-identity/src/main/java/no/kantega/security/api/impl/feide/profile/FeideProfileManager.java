package no.kantega.security.api.impl.feide.profile;

import no.kantega.security.api.profile.ProfileManager;
import no.kantega.security.api.profile.Profile;
import no.kantega.security.api.profile.DefaultProfile;
import no.kantega.security.api.search.SearchResult;
import no.kantega.security.api.common.SystemException;
import no.kantega.security.api.identity.Identity;
import no.kantega.security.api.identity.AuthenticatedIdentity;

import java.util.Properties;

/**
 * User: Anders Skar, Kantega AS
 * Date: May 21, 2007
 * Time: 4:03:40 PM
 */
public class FeideProfileManager implements ProfileManager {
    protected String givenNameAttribute = "givenName";
    protected String surnameAttribute = "sn";
    protected String departmentAttribute = "o";
    protected String emailAttribute = "mail";

    public SearchResult searchProfiles(String string) throws SystemException {
        return null;
    }

    public Profile getProfileForUser(Identity identity) throws SystemException {
        DefaultProfile profile = null;

        if (identity instanceof AuthenticatedIdentity) {
            AuthenticatedIdentity authenticatedIdentity = (AuthenticatedIdentity)identity;
            profile = new DefaultProfile();
            profile.setIdentity(identity);

            Properties attributes = authenticatedIdentity.getRawAttributes();
            profile.setRawAttributes(attributes);

            profile.setSurname(attributes.getProperty(surnameAttribute));
            profile.setGivenName(attributes.getProperty(givenNameAttribute));
            profile.setEmail(attributes.getProperty(emailAttribute));
            if (departmentAttribute != null) {
                profile.setDepartment(attributes.getProperty(departmentAttribute));
            }
        }
        return profile;
    }

    public boolean userHasProfile(Identity identity) throws SystemException {
        if (identity instanceof AuthenticatedIdentity) {
            return true;
        }
        return false;
    }
}
