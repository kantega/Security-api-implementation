package no.kantega.security.api.impl.feide.profile;

import no.kantega.security.api.common.SystemException;
import no.kantega.security.api.identity.AuthenticatedIdentity;
import no.kantega.security.api.identity.Identity;
import no.kantega.security.api.profile.DefaultProfile;
import no.kantega.security.api.profile.Profile;
import no.kantega.security.api.profile.ProfileManager;
import no.kantega.security.api.search.SearchResult;

import java.util.List;
import java.util.Properties;

/**
 * User: Anders Skar, Kantega AS
 * Date: May 21, 2007
 * Time: 4:03:40 PM
 */
public class FeideProfileManager implements ProfileManager {
    protected String displayNameAttribute = "displayName";
    protected String givenNameAttribute = "givenName";
    protected String surnameAttribute = "sn";
    protected String departmentAttribute = "o";
    protected String emailAttribute = "mail";

    public SearchResult<Profile> searchProfiles(String string) throws SystemException {
        return null;
    }

    public SearchResult<Profile> getProfileForUsers(List<Identity> identities) throws SystemException {
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

            if (surnameAttribute != null && surnameAttribute.length() > 0) {
                profile.setSurname(attributes.getProperty(surnameAttribute));
            }

            if (givenNameAttribute != null && givenNameAttribute.length() > 0) {
                profile.setGivenName(attributes.getProperty(givenNameAttribute));
            }

            // Dersom fornavn / etternavn ikke er gitt bruker vi displayName og splitter opp dette
            if (displayNameAttribute != null && displayNameAttribute.length() > 0) {
                if (profile.getSurname() == null || profile.getGivenName() == null) {
                    String displayName = attributes.getProperty(displayNameAttribute);
                    if (displayName != null) {
                        int inx = displayName.lastIndexOf(" ");
                        if (inx == -1) {
                            profile.setGivenName(displayName);
                        } else {
                            profile.setGivenName(displayName.substring(0, inx));
                            profile.setSurname(displayName.substring(inx + 1, displayName.length()));
                        }
                    }
                }
            }

            if (emailAttribute != null && emailAttribute.length() > 0) {
                profile.setEmail(attributes.getProperty(emailAttribute));
            }
            if (departmentAttribute != null && departmentAttribute.length() > 0) {
                profile.setDepartment(attributes.getProperty(departmentAttribute));
            }
        }
        return profile;
    }

    public boolean userHasProfile(Identity identity) throws SystemException {
        return identity instanceof AuthenticatedIdentity;
    }

    public void setDisplayNameAttribute(String displayNameAttribute) {
        this.displayNameAttribute = displayNameAttribute;
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
}
