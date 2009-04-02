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

import no.kantega.security.api.role.RoleManager;
import no.kantega.security.api.role.Role;
import no.kantega.security.api.role.RoleId;
import no.kantega.security.api.role.RoleComparator;
import no.kantega.security.api.impl.common.CompoundManagerConfigurable;
import no.kantega.security.api.common.SystemException;
import no.kantega.security.api.search.SearchResult;
import no.kantega.security.api.search.DefaultSearchResult;
import no.kantega.security.api.identity.Identity;

import java.util.*;

/**
 * User: Anders Skar, Kantega AS
 * Date: Jun 7, 2007
 * Time: 10:54:58 AM
 */
public class CompoundRoleManager extends CompoundManagerConfigurable implements RoleManager {

    public Iterator getAllRoles() throws SystemException {
        List totalResult = new ArrayList();
        for (int i = 0; i < managers.size(); i++) {
            RoleManager rm = (RoleManager)managers.get(i);
            Iterator it = rm.getAllRoles();
            if (it != null) {
                while (it.hasNext()) {
                    totalResult.add(it.next());
                }
            }
        }

        // Sorter lista basert på navn på rolle
        Comparator comparator = new RoleComparator();
        Collections.sort(totalResult, comparator);

        return totalResult.iterator();
    }

    public SearchResult searchRoles(String searchphrase) throws SystemException {
        List totalResult = new ArrayList();
        for (int i = 0; i < managers.size(); i++) {
            RoleManager rm = (RoleManager)managers.get(i);
            SearchResult result = rm.searchRoles(searchphrase);
            if (result != null) {
                Iterator it = result.getAllResults();
                while (it.hasNext()) {
                    totalResult.add(it.next());
                }
            }
        }

        // Sorter lista basert på navn på rolle
        Comparator comparator = new RoleComparator();
        Collections.sort(totalResult, comparator);

        DefaultSearchResult searchResult = new DefaultSearchResult();
        searchResult.setResults(totalResult);

        return searchResult;
    }

    public Role getRoleById(RoleId roleId) throws SystemException {
        for (int i = 0; i < managers.size(); i++) {
            RoleManager rm = (RoleManager)managers.get(i);
            Role role = rm.getRoleById(roleId);
            if (role != null) {
                return role;
            }
        }
        return null;

    }

    public Iterator getRolesForUser(Identity identity) throws SystemException {
        List totalResult = new ArrayList();
        for (int i = 0; i < managers.size(); i++) {
            RoleManager rm = (RoleManager)managers.get(i);
            Iterator it = rm.getRolesForUser(identity);
            if (it != null) {
                while (it.hasNext()) {
                    totalResult.add(it.next());
                }
            }
        }

        // Sorter lista basert på navn på rolle
        Comparator comparator = new RoleComparator();
        Collections.sort(totalResult, comparator);

        return totalResult.iterator();
    }

    public Iterator getUsersWithRole(RoleId roleId) throws SystemException {
        List totalResult = new ArrayList();
        for (int i = 0; i < managers.size(); i++) {
            RoleManager rm = (RoleManager)managers.get(i);
            Iterator it = rm.getUsersWithRole(roleId);
            if (it != null) {
                while (it.hasNext()) {
                    totalResult.add(it.next());
                }
            }
        }

        // Ikke noe poeng i å sortere ettersom dette bare er brukerider...

        return totalResult.iterator();
    }

    public boolean userHasRole(Identity identity, String role) throws SystemException {
        for (int i = 0; i < managers.size(); i++) {
            RoleManager rm = (RoleManager)managers.get(i);
            if (rm.userHasRole(identity, role)) {
                return true;
            }
        }

        return false;
    }
}
