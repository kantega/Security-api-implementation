package no.kantega.security.api.impl.common.role;

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
import no.kantega.security.api.impl.common.CompoundManagerConfigurable;
import no.kantega.security.api.role.Role;
import no.kantega.security.api.role.RoleComparator;
import no.kantega.security.api.role.RoleId;
import no.kantega.security.api.role.RoleManager;
import no.kantega.security.api.search.DefaultRoleSearchResult;
import no.kantega.security.api.search.SearchResult;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/**
 * Provides support for configuring several <code>RoleManager</code>s for a single domain.
 */
public class CompoundRoleManager extends CompoundManagerConfigurable<RoleManager> implements RoleManager {

    public Iterator<Role> getAllRoles() throws SystemException {
        List<Role> totalResult = new ArrayList<>();
        for (RoleManager rm : managers) {
            Iterator<Role> it = rm.getAllRoles();
            if (it != null) {
                while (it.hasNext()) {
                    totalResult.add(it.next());
                }
            }
        }

        // Sorter lista basert p� navn p� rolle
        Collections.sort(totalResult, new RoleComparator());

        return totalResult.iterator();
    }

    public SearchResult<Role> searchRoles(String searchphrase) throws SystemException {
        List<Role> totalResult = new ArrayList<>();
        for (RoleManager rm : managers) {
            SearchResult<Role> result = rm.searchRoles(searchphrase);
            if (result != null) {
                Iterator<Role> it = result.getAllResults();
                while (it.hasNext()) {
                    totalResult.add(it.next());
                }
            }
        }

        // Sorter lista basert p� navn p� rolle
        Collections.sort(totalResult, new RoleComparator());

        DefaultRoleSearchResult searchResult = new DefaultRoleSearchResult();
        searchResult.setResults(totalResult);

        return searchResult;
    }

    public Role getRoleById(RoleId roleId) throws SystemException {
        for (RoleManager rm : managers) {
            Role role = rm.getRoleById(roleId);
            if (role != null) {
                return role;
            }
        }
        return null;

    }

    public Iterator<Role> getRolesForUser(Identity identity) throws SystemException {
        List<Role> totalResult = new ArrayList<>();
        for (RoleManager rm : managers) {
            Iterator<Role> it = rm.getRolesForUser(identity);
            if (it != null) {
                while (it.hasNext()) {
                    totalResult.add(it.next());
                }
            }
        }

        // Sorter lista basert p� navn p� rolle
        Collections.sort(totalResult, new RoleComparator());

        return totalResult.iterator();
    }

    public Iterator<Identity> getUsersWithRole(RoleId roleId) throws SystemException {
        List<Identity> totalResult = new ArrayList<>();
        for (RoleManager rm : managers) {
            Iterator<Identity> it = rm.getUsersWithRole(roleId);
            if (it != null) {
                while (it.hasNext()) {
                    totalResult.add(it.next());
                }
            }
        }

        // Ikke noe poeng i � sortere ettersom dette bare er brukerider...

        return totalResult.iterator();
    }

    public boolean userHasRole(Identity identity, String role) throws SystemException {
        for (RoleManager rm : managers) {
            if (rm.userHasRole(identity, role)) {
                return true;
            }
        }

        return false;
    }
}
