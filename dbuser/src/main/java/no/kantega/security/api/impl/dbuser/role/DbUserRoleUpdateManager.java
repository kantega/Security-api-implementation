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
import no.kantega.security.api.identity.Identity;
import no.kantega.security.api.role.Role;
import no.kantega.security.api.role.RoleId;
import no.kantega.security.api.role.RoleUpdateManager;
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
        getJdbcTemplate().update("DELETE FROM dbuserrole WHERE Domain = ? AND RoleId = ?",
                roleId.getDomain(), roleId.getId());

        // Slett rolletilknytning til brukere
        getJdbcTemplate().update("DELETE FROM dbuserrole2user WHERE RoleDomain = ? AND RoleId = ?",
                roleId.getDomain(), roleId.getId());
    }

    public void saveOrUpdateRole(Role role) throws SystemException {
        if (!role.getDomain().equalsIgnoreCase(domain)) {
            return;
        }

        // Sjekk om profil finnes
        int antallP = getJdbcTemplate().queryForObject("SELECT COUNT(*) FROM dbuserrole WHERE Domain = ? AND RoleId = ?", Integer.class,
                role.getDomain(), role.getId());
        if (antallP > 0) {
            // Oppdater profil
            getJdbcTemplate().update("UPDATE dbuserrole SET RoleName = ? WHERE Domain = ? AND RoleId = ?",
                    role.getName(), role.getDomain(), role.getId() );
        } else {
            // Ny profil
            getJdbcTemplate().update("INSERT INTO dbuserrole (Domain, RoleId, RoleName) VALUES(?,?,?)",
                    role.getDomain(), role.getId(), role.getName());
        }

    }

    public void addUserToRole(Identity identity, RoleId roleId) throws SystemException {
        if (!roleId.getDomain().equalsIgnoreCase(domain)) {
            return;
        }

        // Slett knytningen i tilfelle brukeren har den fra f�r
        removeUserFromRole(identity, roleId);

        // Legg til knytning
        getJdbcTemplate().update("INSERT INTO dbuserrole2user (RoleDomain, RoleId, UserDomain, UserId) VALUES (?,?,?,?)",
                roleId.getDomain(), roleId.getId(), identity.getDomain(), identity.getUserId());


    }

    public void removeUserFromRole(Identity identity, RoleId roleId) throws SystemException {
        if (!roleId.getDomain().equalsIgnoreCase(domain)) {
            return;
        }

        // Slett rolletilknytning til brukere
        getJdbcTemplate().update("DELETE FROM dbuserrole2user WHERE RoleDomain = ? AND RoleId = ? AND UserDomain = ? AND UserId = ?",
                roleId.getDomain(), roleId.getId(), identity.getDomain(), identity.getUserId());
    }

    public void removeUserFromAllRoles(Identity identity) throws SystemException {
        // Slett rolletilknytning til brukere
        getJdbcTemplate().update("DELETE FROM dbuserrole2user WHERE RoleDomain = ? AND UserDomain = ? AND UserId = ?",
                domain, identity.getDomain(), identity.getUserId());
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }
}
