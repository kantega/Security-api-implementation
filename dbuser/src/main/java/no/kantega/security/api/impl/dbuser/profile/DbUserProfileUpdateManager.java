package no.kantega.security.api.impl.dbuser.profile;

import no.kantega.security.api.profile.ProfileUpdateManager;
import no.kantega.security.api.profile.Profile;
import no.kantega.security.api.identity.Identity;
import no.kantega.security.api.common.SystemException;
import org.springframework.jdbc.core.support.JdbcDaoSupport;

import java.util.Properties;
import java.util.Enumeration;

/**
 * User: Anders Skar, Kantega AS
 * Date: Feb 10, 2007
 * Time: 11:55:59 AM
 */
public class DbUserProfileUpdateManager extends JdbcDaoSupport implements ProfileUpdateManager {
    private String domain;

    /**
     * Sletter en brukerprofil, inkludert roller, passord etc
     * @param identity
     * @throws SystemException
     */
    public void deleteProfile(Identity identity) throws SystemException {
        if (!identity.getDomain().equalsIgnoreCase(domain)) {
            return;
        }

        // Slett brukerprofil
        getJdbcTemplate().update("DELETE FROM dbuserprofile WHERE Domain = ? AND UserId = ?", new Object[] {identity.getDomain(), identity.getUserId()});

        // Slett attributter
        getJdbcTemplate().update("DELETE FROM dbuserattributes WHERE Domain = ? AND UserId = ?", new Object[] {identity.getDomain(), identity.getUserId()});

        // Slett passord
        getJdbcTemplate().update("DELETE FROM dbuserpassword WHERE Domain = ? AND UserId = ?", new Object[] {identity.getDomain(), identity.getUserId()});

        // Slett roller
        getJdbcTemplate().update("DELETE FROM dbuserrole2user WHERE UserDomain = ? AND UserId = ?", new Object[] {identity.getDomain(), identity.getUserId()});
    }

    /**
     * Lagrer en brukerprofil inkludert RawAttributes i database.  Dersom domain + userid finnes fra før oppdateres profilen
     * hvis ikke opprettes en ny.  Blanke RawAttributes lagres ikke.
     * @param profile
     * @throws SystemException
     */
    public void saveOrUpdateProfile(Profile profile) throws SystemException {
        Identity identity = profile.getIdentity();

        if (!identity.getDomain().equalsIgnoreCase(domain)) {
            return;
        }

        // Sjekk om profil finnes
        int antallP = getJdbcTemplate().queryForInt("SELECT COUNT(*) FROM dbuserprofile WHERE Domain = ? AND UserId = ?", new Object[] {identity.getDomain(), identity.getUserId()});
        if (antallP > 0) {
            // Oppdater profil
            Object[] param = { profile.getGivenName(), profile.getSurname(), profile.getEmail(), profile.getDepartment(), identity.getDomain(), identity.getUserId() };
            getJdbcTemplate().update("UPDATE dbuserprofile SET GivenName = ?, Surname = ?, Email = ?, Department = ? WHERE Domain = ? AND UserId = ?", param);
        } else {
            // Ny profil
            Object[] param = { identity.getDomain(), identity.getUserId(), profile.getGivenName(), profile.getSurname(), profile.getEmail(), profile.getDepartment() };
            getJdbcTemplate().update("INSERT INTO dbuserprofile (Domain, UserId, GivenName, Surname, Email, Department) VALUES(?,?,?,?,?,?)", param);
        }

        // Lagre attributter
        Properties p = profile.getRawAttributes();
        if (p != null) {
            Enumeration propertyNames = p.propertyNames();
            while (propertyNames.hasMoreElements()) {
                String name =  (String)propertyNames.nextElement();
                String value = p.getProperty(name);
                if (value == null) value = "";

                int antallA = getJdbcTemplate().queryForInt("SELECT COUNT(*) FROM dbuserattributes WHERE Domain = ? AND UserId = ? AND Name = ?", new Object[] {identity.getDomain(), identity.getUserId(), name});
                if (antallA > 0) {
                    if (value.length() == 0) {
                        // Slett property
                        getJdbcTemplate().update("DELETE FROM dbuserattributes WHERE Domain = ? AND UserId = ? AND Name = ?", new Object[] {identity.getDomain(), identity.getUserId(), name});
                    } else {
                        // Oppdater
                        Object[] param = { value, identity.getDomain(), identity.getUserId(), name };
                        getJdbcTemplate().update("UPDATE dbuserattributes SET Value = ? WHERE Domain = ? AND UserId = ? AND Name = ?", param);
                    }
                } else {
                    // Finnes ikke fra før
                    if (value.length() > 0) {
                        Object[] param = { identity.getDomain(), identity.getUserId(), name, value };
                        getJdbcTemplate().update("INSERT INTO dbuserattributes (Domain, UserId, Name, Value) VALUES(?,?,?,?)", param);
                    }
                }
            }
        }
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }
}
