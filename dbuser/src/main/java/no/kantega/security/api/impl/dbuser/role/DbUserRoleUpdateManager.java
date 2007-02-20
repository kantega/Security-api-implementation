package no.kantega.security.api.impl.dbuser.role;

import no.kantega.security.api.role.RoleUpdateManager;
import no.kantega.security.api.role.RoleId;
import no.kantega.security.api.role.Role;
import no.kantega.security.api.common.SystemException;
import no.kantega.security.api.identity.Identity;
import org.springframework.jdbc.core.support.JdbcDaoSupport;

/**
 * User: Anders Skar, Kantega AS
 * Date: Feb 10, 2007
 * Time: 12:34:13 PM
 */
public class DbUserRoleUpdateManager extends JdbcDaoSupport implements RoleUpdateManager {
    private String domain;

    public void deleteRole(RoleId roleId) throws SystemException {
        if (!roleId.getDomain().equalsIgnoreCase(domain)) {
            return;
        }

        // Slett role
        getJdbcTemplate().update("DELETE FROM dbuserrole WHERE Domain = ? AND RoleId = ?", new Object[] {roleId.getDomain(), roleId.getId()});

        // Slett rolletilknytning til brukere
        getJdbcTemplate().update("DELETE FROM dbuserrole2user WHERE RoleDomain = ? AND RoleId = ?", new Object[] {roleId.getDomain(), roleId.getId()});
    }

    public void saveOrUpdateRole(Role role) throws SystemException {
        if (!role.getDomain().equalsIgnoreCase(domain)) {
            return;
        }

        // Sjekk om profil finnes
        int antallP = getJdbcTemplate().queryForInt("SELECT COUNT(*) FROM dbuserrole WHERE Domain = ? AND RoleId = ?", new Object[] {role.getDomain(), role.getId()});
        if (antallP > 0) {
            // Oppdater profil
            Object[] param = { role.getName(), role.getDomain(), role.getId() };
            getJdbcTemplate().update("UPDATE dbuserrole SET RoleName = ? WHERE Domain = ? AND RoleId = ?", param);
        } else {
            // Ny profil
            Object[] param = { role.getDomain(), role.getId(), role.getName() };
            getJdbcTemplate().update("INSERT INTO dbuserrole (Domain, RoleId, RoleName) VALUES(?,?,?)", param);
        }

    }

    public void addUserToRole(Identity identity, RoleId roleId) throws SystemException {
        if (!roleId.getDomain().equalsIgnoreCase(domain)) {
            return;
        }

        // Slett knytningen i tilfelle brukeren har den fra før
        removeUserFromRole(identity, roleId);

        // Legg til knytning
        getJdbcTemplate().update("INSERT INTO dbuserrole2user (RoleDomain, RoleId, UserDomain, UserId) VALUES (?,?,?,?)",
                new Object[] {roleId.getDomain(), roleId.getId(), identity.getDomain(), identity.getUserId()});


    }

    public void removeUserFromRole(Identity identity, RoleId roleId) throws SystemException {
        if (!roleId.getDomain().equalsIgnoreCase(domain)) {
            return;
        }

        // Slett rolletilknytning til brukere
        getJdbcTemplate().update("DELETE FROM dbuserrole2user WHERE RoleDomain = ? AND RoleId = ? AND UserDomain = ? AND UserId = ?",
                new Object[] {roleId.getDomain(), roleId.getId(), identity.getDomain(), identity.getUserId()});
    }

    public void removeUserFromAllRoles(Identity identity) throws SystemException {
        // Slett rolletilknytning til brukere
        getJdbcTemplate().update("DELETE FROM dbuserrole2user WHERE RoleDomain = ? AND UserDomain = ? AND UserId = ?", new Object[] {domain, identity.getDomain(), identity.getUserId()});
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }
}
