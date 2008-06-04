package no.kantega.security.api.impl.dbuser.role;

import no.kantega.security.api.common.SystemException;
import no.kantega.security.api.identity.DefaultIdentity;
import no.kantega.security.api.identity.Identity;
import no.kantega.security.api.role.DefaultRole;
import no.kantega.security.api.role.Role;
import no.kantega.security.api.role.RoleId;
import no.kantega.security.api.role.RoleManager;
import no.kantega.security.api.search.DefaultSearchResult;
import no.kantega.security.api.search.SearchResult;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.support.JdbcDaoSupport;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * User: Anders Skar, Kantega AS
 * Date: Jan 15, 2007
 * Time: 6:49:35 PM
 */
public class DbUserRoleManager extends JdbcDaoSupport implements RoleManager  {
    private String domain;

    public Iterator getAllRoles() throws SystemException {
        List results = getJdbcTemplate().query("SELECT * from dbuserrole ORDER BY Domain, RoleName", new RoleRowMapper());
        return results.iterator();
    }

    public SearchResult searchRoles(String name) throws SystemException {
        List params = new ArrayList();

        String query = "RoleName LIKE ? AND Domain = ?";
        params.add(name + "%");
        params.add(domain);

        String sql = "SELECT * from dbuserrole WHERE " + query + " ORDER BY Domain, RoleName";
        List results = getJdbcTemplate().query(sql, params.toArray(), new RoleRowMapper());

        DefaultSearchResult result = new DefaultSearchResult();
        result.setResults(results);
        return result;

    }

    public Role getRoleById(RoleId roleId) throws SystemException {
        if (!roleId.getDomain().equalsIgnoreCase(domain)) {
            return null;
        }

        List roles = getJdbcTemplate().query("SELECT * FROM dbuserrole WHERE Domain = ? AND RoleId  = ?", new Object[] {roleId.getDomain(), roleId.getId()}, new RoleRowMapper());
        if (roles != null && roles.size() == 1) {
            return (Role)roles.get(0);
        } else {
            return null;
        }
    }

    public Iterator getRolesForUser(Identity identity) throws SystemException {
        List results = getJdbcTemplate().query("SELECT dbuserrole.* FROM dbuserrole, dbuserrole2user WHERE " +
                "dbuserrole.Domain = dbuserrole2user.RoleDomain AND " +
                "dbuserrole.RoleId = dbuserrole2user.RoleId AND " +
                "dbuserrole2user.UserDomain = ? AND dbuserrole2user.UserId = ?",
                new Object[] {identity.getDomain(), identity.getUserId()}, new RoleRowMapper());
        return results.iterator();
    }

    public Iterator getUsersWithRole(RoleId roleId) throws SystemException {
        List results = getJdbcTemplate().query("SELECT * FROM dbuserrole2user WHERE " +
                "dbuserrole2user.RoleDomain = ? AND dbuserrole2user.RoleId = ?",
                new Object[] {roleId.getDomain(), roleId.getId()}, new IdentityRowMapper());
        return results.iterator();
    }


    public boolean userHasRole(Identity identity, String role) throws SystemException {
        int antall = getJdbcTemplate().queryForInt("SELECT COUNT(*) FROM dbuserrole2user WHERE RoleId IN (SELECT RoleId FROM dbuserrole WHERE RoleName = ?) AND UserId = ? AND UserDomain = ?",
                new Object[] {role, identity.getUserId(), identity.getDomain()} );

        return antall > 0;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    private class RoleRowMapper implements RowMapper {

        public Object mapRow(ResultSet rs, int i) throws SQLException {
            DefaultRole role = new DefaultRole();
            role.setId(rs.getString("RoleId"));
            role.setDomain(rs.getString("Domain"));
            role.setName(rs.getString("RoleName"));
            return role;
        }


    }

    private class IdentityRowMapper implements RowMapper {

        public Object mapRow(ResultSet rs, int i) throws SQLException {
            DefaultIdentity identity = new DefaultIdentity();
            identity.setUserId(rs.getString("UserId"));
            identity.setDomain(rs.getString("UserDomain"));
            return identity;
        }


    }
}
