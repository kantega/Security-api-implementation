package no.kantega.security.api.impl.dbuser.profile;

import no.kantega.security.api.common.SystemException;
import no.kantega.security.api.identity.DefaultIdentity;
import no.kantega.security.api.identity.Identity;
import no.kantega.security.api.impl.dbuser.util.HSQLDBDatabaseCreator;
import no.kantega.security.api.profile.DefaultProfile;
import no.kantega.security.api.profile.Profile;
import no.kantega.security.api.search.SearchResult;
import org.junit.Before;
import org.junit.Test;

import javax.sql.DataSource;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class DbUserProfileManagerTest {
    private final static String DOMAIN = "mydomain";
    private Profile donald;
    private Profile dolly;
    private Profile threeNames;
    private DbUserProfileManager profileManager;


    @Before
    public void setUp() throws SystemException {
        DataSource dataSource = new HSQLDBDatabaseCreator("dbuser", getClass().getClassLoader().getResourceAsStream("dbuser.sql")).createDatabase();
        profileManager = new DbUserProfileManager();
        profileManager.setDomain(DOMAIN);
        profileManager.setDataSource(dataSource);
        profileManager.setNameQuerier(new DbNameAndUserIdQuerier());

        DbUserProfileUpdateManager profileUpdateManager = new DbUserProfileUpdateManager();
        profileUpdateManager.setDomain(DOMAIN);
        profileUpdateManager.setDataSource(dataSource);


        donald = createUserProfile("Donald", "Duck");
        profileUpdateManager.saveOrUpdateProfile(donald);

        dolly = createUserProfile("Dolly", "Duck");
        profileUpdateManager.saveOrUpdateProfile(dolly);

        threeNames = createUserProfile("Skrue", "Mc Duck");
        profileUpdateManager.saveOrUpdateProfile(threeNames);

    }

    @Test
    public void testCreateAndGetUsers() throws SystemException {
        List<Identity> identities = new ArrayList<Identity>();
        identities.add(donald.getIdentity());
        identities.add(dolly.getIdentity());

        SearchResult<Profile> profiles = profileManager.getProfileForUsers(identities);
        assertEquals(2, profiles.getSize());

    }

    @Test
    public void shouldFindUsersFromSurname() throws SystemException {
        SearchResult<Profile> profiles = profileManager.searchProfiles("Duck");
        assertEquals(3, profiles.getSize());
    }

    @Test
    public void shouldFindUsersWithDoubleSurname() throws SystemException {
        SearchResult<Profile> profiles = profileManager.searchProfiles("Skrue Mc Duck");
        assertEquals(1, profiles.getSize());
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
