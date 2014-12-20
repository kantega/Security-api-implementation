package no.kantega.security.api.impl.compound.profile;

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
import no.kantega.security.api.impl.compound.CompoundManagerConfigurable;
import no.kantega.security.api.profile.Profile;
import no.kantega.security.api.profile.ProfileComparator;
import no.kantega.security.api.profile.ProfileManager;
import no.kantega.security.api.search.DefaultProfileSearchResult;
import no.kantega.security.api.search.SearchResult;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/**
 * Supports searching a list of <code>ProfileManager</code>s to find <code>Profile</code>s
 */
public class CompoundUserProfileManager extends CompoundManagerConfigurable<ProfileManager> implements ProfileManager {

    public SearchResult<Profile> searchProfiles(String searchphrase) throws SystemException {
        List<Profile> totalResult = new ArrayList<>();
        for (ProfileManager pm : managers) {
            SearchResult<Profile> result = pm.searchProfiles(searchphrase);
            if (result != null) {
                Iterator<Profile> it = result.getAllResults();
                while (it.hasNext()) {
                    totalResult.add(it.next());
                }
            }
        }

        // Sorter lista basert p� navn p� brukere
        Collections.sort(totalResult, new ProfileComparator());

        DefaultProfileSearchResult searchResult = new DefaultProfileSearchResult();
        searchResult.setResults(totalResult);

        return searchResult;
    }

    public Profile getProfileForUser(Identity identity) throws SystemException {
        for (ProfileManager pm : managers) {
            Profile profile = pm.getProfileForUser(identity);
            if (profile != null) {
                return profile;
            }
        }
        return null;
    }

    public SearchResult<Profile> getProfileForUsers(List<Identity> identities) throws SystemException {
        List<Profile> profiles = new ArrayList<>();
        for (Identity identity : identities) {
            Profile profile = getProfileForUser(identity);
            if (profile != null) {
                profiles.add(profile);
            }
        }
        DefaultProfileSearchResult searchResult = new DefaultProfileSearchResult();
        searchResult.setResults(profiles);
        return searchResult;
    }

    public boolean userHasProfile(Identity identity) throws SystemException {
        for (ProfileManager pm : managers) {
            if (pm.userHasProfile(identity)) {
                return true;
            }
        }

        return false;
    }
}
