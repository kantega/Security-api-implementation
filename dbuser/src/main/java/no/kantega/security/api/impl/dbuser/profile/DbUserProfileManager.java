package no.kantega.security.api.impl.dbuser.profile;

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
import no.kantega.security.api.profile.DefaultProfile;
import no.kantega.security.api.profile.Profile;
import no.kantega.security.api.profile.ProfileManager;
import no.kantega.security.api.search.DefaultProfileSearchResult;
import no.kantega.security.api.search.SearchResult;
import org.springframework.jdbc.core.RowCallbackHandler;
import org.springframework.jdbc.core.simple.ParameterizedRowMapper;
import org.springframework.jdbc.core.simple.SimpleJdbcDaoSupport;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * User: Anders Skar, Kantega AS
 * Date: Jan 15, 2007
 * Time: 6:48:38 PM
 */
public class
        DbUserProfileManager extends SimpleJdbcDaoSupport implements ProfileManager {
    private String domain;



    private AbstractDbNameQuerier querier;

    /**
     * S�ker etter en profil.  S�kes i b�de fornavn og etternavn.
     * @param name - Navn som skal s�kes etter
     * @return
     * @throws SystemException
     */
    public SearchResult<Profile> searchProfiles(String name) throws SystemException {
        String query;

        WhereClause clause = querier.getQuery(name);
        query = clause.getWherePart();
        if(query.length() > 0) {
            query += " AND ";
        }

        query += " Domain = '" + domain + "'";

        String sql = "SELECT * from dbuserprofile WHERE " + query + " ORDER BY GivenName, Surname";
        List<Profile> results = getSimpleJdbcTemplate().query(sql, new UserProfileRowMapper(), clause.getParams().toArray());

        DefaultProfileSearchResult result = new DefaultProfileSearchResult();
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
            getJdbcTemplate().query("SELECT * from dbuserattributes WHERE Domain = ? AND UserId = ?", new Object[] {identity.getDomain(), identity.getUserId()}, callback);
            p.setRawAttributes(callback.getAttributes());
            return p;
        }

        return null;
    }

    public SearchResult<Profile> getProfileForUsers(List<Identity> identities) throws SystemException {
        if (identities == null) {
            return new DefaultProfileSearchResult();
        }

        List<String> param  =  new ArrayList<String>();


        String query = "(";

        boolean identitiesWithThisDomainFound = false;
        for (Identity identity : identities) {
            if (identity.getDomain().equalsIgnoreCase(domain)) {
                if (identitiesWithThisDomainFound) {
                    query += " OR ";
                }
                query += "UserId = ?";
                param.add(identity.getUserId());
                identitiesWithThisDomainFound = true;
            }
        }
        query += ")";

        if (!identitiesWithThisDomainFound) {
            return new DefaultProfileSearchResult();
        }

        query += " AND Domain = ?";
        param.add(domain);

        String sql = "SELECT * from dbuserprofile WHERE " + query + " ORDER BY GivenName, Surname";
        List<Profile> results = getSimpleJdbcTemplate().query(sql, new UserProfileRowMapper(), param.toArray());

        DefaultProfileSearchResult result = new DefaultProfileSearchResult();
        result.setResults(results);
        return result;
    }

    public boolean userHasProfile(Identity identity) throws SystemException {
        if (!identity.getDomain().equalsIgnoreCase(domain)) {
            return false;
        }

        int antall = getJdbcTemplate().queryForInt("SELECT COUNT(*) FROM dbuserprofile WHERE Domain = ? AND UserId = ?", new Object[]{identity.getDomain(), identity.getUserId()});
        return antall > 0;

    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public void setNameQuerier(AbstractDbNameQuerier querier) {
        this.querier = querier;
    }

    private class UserProfileRowMapper implements ParameterizedRowMapper<Profile> {

        public Profile mapRow(ResultSet rs, int i) throws SQLException {
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
            if (value == null) value = "";

            p.setProperty(name, value);
        }

        public Properties getAttributes() {
            return p;
        }
    }

    /**
     * Ensure that querier is defined after the ProfileManager has been initialized.
     * @throws Exception
     */
    @Override
    protected void initDao() throws Exception {
        super.initDao();
        if (querier == null) {
            querier = new DbNameAndUserIdQuerier();
        }
    }
}
