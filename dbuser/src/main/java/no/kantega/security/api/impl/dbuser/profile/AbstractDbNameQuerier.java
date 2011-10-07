package no.kantega.security.api.impl.dbuser.profile;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by IntelliJ IDEA.
 * User: sjukva
 */
public abstract class AbstractDbNameQuerier {

    private List<String> param;
    private StringBuffer query;

    public WhereClause getQuery(String name) {
        if (name == null) {
            return WhereClause.EMPTY;
        }
        param = new ArrayList<String>();
        query = new StringBuffer();
        addEntireNameMatchingQuery(name);
        addCombinatoryNameMatchingQuery(name);
        return new WhereClause(query.toString(), param);
    }



    private void addEntireNameMatchingQuery(String name) {
        if (name.length() > 0) {
            query.append(getEntireNameMatchingQuery());
            for(int i = 0; i < getNrOfNameMatchingParams(); i++) {
                param.add(addWildcard(name));
            }
        }
    }

    private void addCombinatoryNameMatchingQuery(String name) {
        String[] names = name.split(" ");
        for(int i = 1; i < names.length; i++){
            String givenName = concatSubArray(names, 0, i);
            String surname = concatSubArray(names, i, names.length);
            param.add(addWildcard(givenName));
            param.add(addWildcard(surname));
            query.append(" OR (GivenName LIKE ? AND Surname LIKE ?)");
        }
    }

    private String concatSubArray(String[] names, int startIndexInclusive, int endIndexExclusive) {
        return StringUtils.join(ArrayUtils.subarray(names, startIndexInclusive, endIndexExclusive), " ");
    }


    public abstract String getEntireNameMatchingQuery();

    public abstract int getNrOfNameMatchingParams();


    private String addWildcard(String name) {
        return "%" + name + "%";
    }
}
