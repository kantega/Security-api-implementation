package no.kantega.security.api.impl.dbuser.role;

/*
 * Copyright 2009 Kantega AS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import no.kantega.security.api.common.SystemException;
import no.kantega.security.api.identity.DefaultIdentity;
import no.kantega.security.api.identity.Identity;
import no.kantega.security.api.role.DefaultRole;
import no.kantega.security.api.role.Role;
import no.kantega.security.api.role.RoleId;
import no.kantega.security.api.role.RoleManager;
import no.kantega.security.api.search.DefaultRoleSearchResult;
import no.kantega.security.api.search.SearchResult;
import org.springframework.jdbc.core.simple.ParameterizedRowMapper;
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

    public Iterator<Role> getAllRoles() throws SystemException {
        List<Role> results = getJdbcTemplate().query("SELECT * from dbuserrole ORDER BY Domain, RoleName", new RoleRowMapper());
        return results.iterator();
    }

    public SearchResult<Role> searchRoles(String name) throws SystemException {
        List<String> params = new ArrayList<>();

        String query = "RoleName LIKE ? AND Domain = ?";
        params.add(name + "%");
        params.add(domain);

        String sql = "SELECT * from dbuserrole WHERE " + query + " ORDER BY Domain, RoleName";
        List<Role> results = getJdbcTemplate().query(sql, new RoleRowMapper(), params.toArray());

        DefaultRoleSearchResult result = new DefaultRoleSearchResult();
        result.setResults(results);
        return result;

    }

    public Role getRoleById(RoleId roleId) throws SystemException {
        if (!roleId.getDomain().equalsIgnoreCase(domain)) {
            return null;
        }

        List roles = getJdbcTemplate().query("SELECT * FROM dbuserrole WHERE Domain = ? AND RoleId  = ?", new RoleRowMapper(),
                roleId.getDomain(), roleId.getId());
        if (roles != null && roles.size() == 1) {
            return (Role)roles.get(0);
        } else {
            return null;
        }
    }

    public Iterator<Role> getRolesForUser(Identity identity) throws SystemException {
        List<Role> results = getJdbcTemplate().query("SELECT dbuserrole.* FROM dbuserrole, dbuserrole2user WHERE " +
                "dbuserrole.Domain = dbuserrole2user.RoleDomain AND " +
                "dbuserrole.RoleId = dbuserrole2user.RoleId AND " +
                "dbuserrole2user.UserDomain = ? AND dbuserrole2user.UserId = ?", new RoleRowMapper(),
                identity.getDomain(), identity.getUserId());
        return results.iterator();
    }

    public Iterator<Identity> getUsersWithRole(RoleId roleId) throws SystemException {
        List<Identity> results = getJdbcTemplate().query("SELECT * FROM dbuserrole2user WHERE " +
                "dbuserrole2user.RoleDomain = ? AND dbuserrole2user.RoleId = ?", new IdentityRowMapper(),
                roleId.getDomain(), roleId.getId());
        return results.iterator();
    }


    public boolean userHasRole(Identity identity, String role) throws SystemException {
        int antall = getJdbcTemplate().queryForObject("SELECT COUNT(*) FROM dbuserrole2user WHERE RoleId IN (SELECT RoleId FROM dbuserrole WHERE RoleName = ?) AND UserId = ? AND UserDomain = ?",
                Integer.class, role, identity.getUserId(), identity.getDomain());

        return antall > 0;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    private class RoleRowMapper implements ParameterizedRowMapper<Role> {

        public Role mapRow(ResultSet rs, int i) throws SQLException {
            DefaultRole role = new DefaultRole();
            role.setId(rs.getString("RoleId"));
            role.setDomain(rs.getString("Domain"));
            role.setName(rs.getString("RoleName"));
            return role;
        }
    }

    private class IdentityRowMapper implements ParameterizedRowMapper<Identity> {

        public Identity mapRow(ResultSet rs, int i) throws SQLException {
            DefaultIdentity identity = new DefaultIdentity();
            identity.setUserId(rs.getString("UserId"));
            identity.setDomain(rs.getString("UserDomain"));
            return identity;
        }
    }
}
