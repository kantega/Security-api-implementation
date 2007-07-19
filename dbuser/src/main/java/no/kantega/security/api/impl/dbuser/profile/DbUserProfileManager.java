package no.kantega.security.api.impl.dbuser.profile;

import org.springframework.jdbc.core.support.JdbcDaoSupport;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.RowCallbackHandler;
import no.kantega.security.api.profile.ProfileManager;
import no.kantega.security.api.profile.Profile;
import no.kantega.security.api.profile.DefaultProfile;
import no.kantega.security.api.search.SearchResult;
import no.kantega.security.api.search.DefaultSearchResult;
import no.kantega.security.api.common.SystemException;
import no.kantega.security.api.identity.Identity;
import no.kantega.security.api.identity.DefaultIdentity;
import no.kantega.security.api.role.DefaultRole;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Properties;

/**
 * User: Anders Skar, Kantega AS
 * Date: Jan 15, 2007
 * Time: 6:48:38 PM
 */
public class DbUserProfileManager extends JdbcDaoSupport implements ProfileManager {
    private String domain;

    /**
     * Søker etter en profil.  Søkes i både fornavn og etternavn.
     * @param name - Navn som skal søkes etter
     * @return
     * @throws SystemException
     */
    public SearchResult searchProfiles(String name) throws SystemException {
        // TODO: Strip illegal chars

        String query = " (GivenName LIKE '%" + name + "%' OR Surname LIKE '%" + name + "%')";

        // Dersom brukeren har tastet inn flere navn antar vi at det siste er etternavn
        if (name.indexOf(' ') != -1) {
            String givenName = name.substring(0, name.lastIndexOf(' ')).trim();
            String surname = name.substring(name.lastIndexOf(' '), name.length()).trim();
            query += " OR (GivenName LIKE '%" + givenName + "%' AND Surname LIKE '%" + surname + "%')";
        }
        query += " AND Domain = '" + domain + "'";

        String sql = "SELECT * from dbuserprofile WHERE " + query + " ORDER BY GivenName, Surname";
        List results = getJdbcTemplate().query(sql, new UserProfileRowMapper());

        DefaultSearchResult result = new DefaultSearchResult();
        result.setResults(results);
        return result;
    }

    /**
     * Hent brukerprofil for angitt identitet
     * @param identity
     * @return
     * @throws SystemException
     */
    public Profile getProfileForUser(Identity identity) throws SystemException {
        if (!identity.getDomain().equalsIgnoreCase(domain)) {
            return null;
        }

        List profiles = getJdbcTemplate().query("SELECT * FROM dbuserprofile WHERE Domain = ? AND UserId = ?", new Object[] {identity.getDomain(), identity.getUserId()}, new UserProfileRowMapper());
        if (profiles != null && profiles.size() == 1) {
            DefaultProfile p = (DefaultProfile)profiles.get(0);

            // Hent extended properties
            UserAttributesCallbackHandler callback = new UserAttributesCallbackHandler();
            getJdbcTemplate().query("SELECT * from dbuserattributes WHERE Domain = ? AND UserId = ?", new Object[] {identity.getDomain(), identity.getUserId()}, new UserAttributesCallbackHandler());
            p.setRawAttributes(callback.getAttributes());
            return p;
        }

        return null;
    }

    public boolean userHasProfile(Identity identity) throws SystemException {
        if (!identity.getDomain().equalsIgnoreCase(domain)) {
            return false;
        }

        int antall = getJdbcTemplate().queryForInt("SELECT COUNT(*) FROM dbuserprofile WHERE Domain = ? AND UserId = ?", new Object[] {identity.getDomain(), identity.getUserId()});
        return antall > 0;

    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    private class UserProfileRowMapper implements RowMapper {

        public Object mapRow(ResultSet rs, int i) throws SQLException {
            DefaultProfile profile = new DefaultProfile();

            DefaultIdentity identity = new DefaultIdentity();
            identity.setUserId(rs.getString("UserId"));
            identity.setDomain(rs.getString("Domain"));
            profile.setIdentity(identity);

            profile.setGivenName(rs.getString("GivenName"));
            profile.setSurname(rs.getString("SurName"));
            profile.setEmail(rs.getString("Email"));
            profile.setDepartment(rs.getString("Department"));

            return profile;
        }
    }

    private class UserAttributesCallbackHandler implements RowCallbackHandler {
        Properties p;

        UserAttributesCallbackHandler() {
            p = new Properties();
        }

        public void processRow(ResultSet rs) throws SQLException {
            String name = rs.getString("Name");
            String value = rs.getString("Value");
            p.setProperty(name, value);
        }

        public Properties getAttributes() {
            return p;
        }
    }
}
