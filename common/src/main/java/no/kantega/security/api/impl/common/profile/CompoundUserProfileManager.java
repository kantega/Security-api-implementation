package no.kantega.security.api.impl.common.profile;

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

import no.kantega.security.api.impl.common.CompoundManagerConfigurable;
import no.kantega.security.api.profile.ProfileManager;
import no.kantega.security.api.profile.Profile;
import no.kantega.security.api.profile.ProfileComparator;
import no.kantega.security.api.search.SearchResult;
import no.kantega.security.api.search.DefaultSearchResult;
import no.kantega.security.api.common.SystemException;
import no.kantega.security.api.identity.Identity;

import java.util.*;

/**
 * User: Anders Skar, Kantega AS
 * Date: Jun 7, 2007
 * Time: 10:34:39 AM
 */
public class CompoundUserProfileManager extends CompoundManagerConfigurable implements ProfileManager {
    public SearchResult searchProfiles(String searchphrase) throws SystemException {
        List totalResult = new ArrayList();
        for (int i = 0; i < managers.size(); i++) {
            ProfileManager pm = (ProfileManager)managers.get(i);
            SearchResult result = pm.searchProfiles(searchphrase);
            if (result != null) {
                Iterator it = result.getAllResults();
                while (it.hasNext()) {
                    totalResult.add(it.next());
                }
            }
        }

        // Sorter lista basert på navn på brukere
        Comparator comparator = new ProfileComparator();
        Collections.sort(totalResult, comparator);

        DefaultSearchResult searchResult = new DefaultSearchResult();
        searchResult.setResults(totalResult);

        return searchResult;
    }

    public Profile getProfileForUser(Identity identity) throws SystemException {
        for (int i = 0; i < managers.size(); i++) {
            ProfileManager pm = (ProfileManager)managers.get(i);
            Profile profile = pm.getProfileForUser(identity);
            if (profile != null) {
                return profile;
            }
        }
        return null;
    }

    public boolean userHasProfile(Identity identity) throws SystemException {
        for (int i = 0; i < managers.size(); i++) {
            ProfileManager pm = (ProfileManager)managers.get(i);
            if (pm.userHasProfile(identity)) {
                return true;
            }
        }

        return false;
    }
}
