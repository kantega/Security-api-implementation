package no.kantega.security.api.impl.dbuser.profile;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by IntelliJ IDEA.
 * User: sjukva
 * Will genereate a query using all combinations of names
 * Ex: given 'Jon Arvid Jonsen'
 * will query for all combinations of givenname/surname as
 * 'Jon Arvid'/'Jonsen' and 'Jon'/'Arvid Jonsen'
 */
public class DbNameAndUserIdQuerier extends AbstractDbNameQuerier {
    private String stdQuery = " (GivenName LIKE ? OR Surname LIKE ? OR UserId LIKE ?)";

    @Override
    public String getEntireNameMatchingQuery() {
        return stdQuery;
    }


    @Override
    public int getNrOfNameMatchingParams() {
        return StringUtils.countMatches(stdQuery, "?");
    }
}
