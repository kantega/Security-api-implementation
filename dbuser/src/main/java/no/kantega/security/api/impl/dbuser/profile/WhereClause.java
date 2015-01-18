package no.kantega.security.api.impl.dbuser.profile;

import java.util.Collections;
import java.util.List;

/**
 * Created by IntelliJ IDEA.
 * User: sjukva
 */
public class WhereClause {
    private String query;
    private List<String> param;
    public static final WhereClause EMPTY = new WhereClause("", Collections.<String>emptyList());

    public WhereClause(String query, List<String> param) {
        this.query = query;
        this.param = param;
    }

    public String getWherePart() {
        return query;
    }

    public List<String> getParams() {
        return param;
    }
}
