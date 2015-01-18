package no.kantega.security.api.impl.dbuser.profile;

import org.apache.commons.lang.StringUtils;

/**
 * Created by IntelliJ IDEA.
 * User: sjukva
 * Will genereate a query using all combinations of names
 * Ex: given 'Jon Arvid Jonsen'
 * will query for all combinations of givenname/surname as
 * 'Jon Arvid'/'Jonsen' and 'Jon'/'Arvid Jonsen'
 */
public class DbNameQuerier extends AbstractDbNameQuerier {
    private String stdQuery = " (GivenName LIKE ? OR Surname LIKE ?)";

    @Override
    public String getEntireNameMatchingQuery() {
        return stdQuery;
    }


    @Override
    public int getNrOfNameMatchingParams() {
        return StringUtils.countMatches(stdQuery, "?");
    }
}