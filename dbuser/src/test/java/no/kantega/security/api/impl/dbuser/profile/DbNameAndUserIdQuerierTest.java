package no.kantega.security.api.impl.dbuser.profile;

import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static junit.framework.Assert.assertEquals;
import static org.fest.assertions.Assertions.assertThat;

/**
 * Created by IntelliJ IDEA.
 * User: sjukva
 */
public class DbNameAndUserIdQuerierTest {

    @Test
    public void shouldReturnEmptyQueryForEmptyName(){
        DbNameAndUserIdQuerier querier = getDbNameQuerier();
        WhereClause clause =  querier.getQuery("");
        assertEquals("", clause.getWherePart() );
        assertEquals(0, clause.getParams().size());
    }

    private DbNameAndUserIdQuerier getDbNameQuerier() {
        return new DbNameAndUserIdQuerier();
    }

    @Test
    public void shouldHandleNullName(){
        DbNameAndUserIdQuerier querier = getDbNameQuerier();
        WhereClause clause =  querier.getQuery(null);
        assertEquals("", clause.getWherePart() );
        assertEquals(0, clause.getParams().size());
    }


    @Test
    public void shouldReturnStandardqueryForSingleName(){
        DbNameAndUserIdQuerier querier = getDbNameQuerier();
        String name = "Harald";
        WhereClause clause = querier.getQuery(name);
        assertEquals(getStdQuery(), clause.getWherePart());
        assertEquals("%Harald%", clause.getParams().get(0));
        assertThat(getStdParams(name)).isEqualTo(clause.getParams());
    }

    @Test
    public void shouldReturnStandardQueryAndSplittedQueryForTwoNames(){
        String stdquery = getStdQuery();
        String splitnameQuery = getSingleSplitNameQuery();
        DbNameAndUserIdQuerier querier = getDbNameQuerier();
        String name = "Harald Knausen";
        WhereClause clause = querier.getQuery(name);
        assertEquals(stdquery + splitnameQuery, clause.getWherePart());

        assertThat("%Harald%").isEqualTo(clause.getParams().get(3));
        assertThat("%Knausen%").isEqualTo(clause.getParams().get(4));
    }

    @Test
    public void shouldReturnStandardQueryAndSplittedQueryForThreeNames(){
        String stdquery = getStdQuery();
        String splitnameQuery = getSingleSplitNameQuery();
        DbNameAndUserIdQuerier querier = getDbNameQuerier();
        String name = "Harald Knaus Knausen";
        WhereClause clause = querier.getQuery(name);
        assertEquals(stdquery + splitnameQuery + splitnameQuery, clause.getWherePart());
        assertThat("%Harald%").isEqualTo(clause.getParams().get(3));
        assertThat("%Knaus Knausen%").isEqualTo(clause.getParams().get(4));
        assertThat("%Harald Knaus%").isEqualTo(clause.getParams().get(5));
        assertThat("%Knausen%").isEqualTo(clause.getParams().get(6));
    }


    @Test
    public void shouldReturnStandardQueryAndSplittedQueryForFourNames(){
        String stdquery = getStdQuery();
        String splitnameQuery = getSingleSplitNameQuery();
        DbNameAndUserIdQuerier querier = getDbNameQuerier();
        String name = "Harald Jon Knaus Knausen";
        WhereClause clause = querier.getQuery(name);
        assertEquals(stdquery + splitnameQuery + splitnameQuery + splitnameQuery, clause.getWherePart());
        assertThat("%Harald%").isEqualTo(clause.getParams().get(3));
        assertThat("%Jon Knaus Knausen%").isEqualTo(clause.getParams().get(4));
        assertThat("%Harald Jon%").isEqualTo(clause.getParams().get(5));
        assertThat("%Knaus Knausen%").isEqualTo(clause.getParams().get(6));
        assertThat("%Harald Jon Knaus%").isEqualTo(clause.getParams().get(7));
        assertThat("%Knausen%").isEqualTo(clause.getParams().get(8));
    }


    private String getStdQuery() {
        return " (GivenName LIKE ? OR Surname LIKE ? OR UserId LIKE ?)";
    }

    private String getSingleSplitNameQuery() {
        return " OR (GivenName LIKE ? AND Surname LIKE ?)";
    }

    private List<String> getStdParams(String name) {
        String[] params = {"%" + name + "%", "%" + name + "%", "%" + name + "%"};
        return Arrays.asList(params);
    }
}
