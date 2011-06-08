package no.kantega.security.api.impl.dbuser.profile;

import no.kantega.security.api.common.SystemException;
import no.kantega.security.api.identity.DefaultIdentity;
import no.kantega.security.api.identity.Identity;
import no.kantega.security.api.impl.dbuser.util.HSQLDBDatabaseCreator;
import no.kantega.security.api.profile.DefaultProfile;
import no.kantega.security.api.profile.Profile;
import no.kantega.security.api.search.SearchResult;
import org.junit.Test;

import javax.sql.DataSource;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class DbUserProfileManagerTest {
    private final static String DOMAIN = "mydomain";

    @Test
    public void testCreateAndGetUsers() throws SystemException {
        DataSource dataSource = new HSQLDBDatabaseCreator("dbuser", getClass().getClassLoader().getResourceAsStream("dbuser.sql")).createDatabase();
        DbUserProfileManager profileManager = new DbUserProfileManager();
        profileManager.setDomain(DOMAIN);
        profileManager.setDataSource(dataSource);

        DbUserProfileUpdateManager profileUpdateManager = new DbUserProfileUpdateManager();
        profileUpdateManager.setDomain(DOMAIN);
        profileUpdateManager.setDataSource(dataSource);


        Profile donald = createUserProfile("Donald", "Duck");
        profileUpdateManager.saveOrUpdateProfile(donald);

        Profile dolly = createUserProfile("Dolly", "Duck");
        profileUpdateManager.saveOrUpdateProfile(dolly);

        List<Identity> identities = new ArrayList<Identity>();
        identities.add(donald.getIdentity());
        identities.add(dolly.getIdentity());

        SearchResult<Profile> profiles = profileManager.getProfileForUsers(identities);
        assertEquals(profiles.getSize(), 2);
    }

    private Profile createUserProfile(String givenName, String surname) {
        DefaultProfile profile = new DefaultProfile();
        profile.setGivenName(givenName);
        profile.setSurname(surname);
        profile.setEmail(givenName + "@andeby.no");

        DefaultIdentity identity = new DefaultIdentity();
        identity.setUserId(givenName.toLowerCase());
        identity.setDomain(DOMAIN);

        profile.setIdentity(identity);

        return profile;
    }
}
