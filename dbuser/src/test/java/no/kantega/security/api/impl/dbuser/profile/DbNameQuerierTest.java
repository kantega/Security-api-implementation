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
public class DbNameQuerierTest {

    @Test
    public void shouldReturnEmptyQueryForEmptyName(){
        DbNameQuerier querier = getNameQuerier();
        WhereClause clause =  querier.getQuery("");
        assertEquals("", clause.getWherePart() );
        assertEquals(0, clause.getParams().size());
    }

    @Test
    public void shouldHandleNullName(){
        DbNameQuerier querier = getNameQuerier();
        WhereClause clause =  querier.getQuery(null);
        assertEquals("", clause.getWherePart() );
        assertEquals(0, clause.getParams().size());
    }


    @Test
    public void shouldReturnStandardqueryForSingleName(){
        DbNameQuerier querier = getNameQuerier();
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
        DbNameQuerier querier = getNameQuerier();
        String name = "Harald Knausen";
        WhereClause clause = querier.getQuery(name);
        assertEquals(stdquery + splitnameQuery, clause.getWherePart());

        assertThat("%Harald%").isEqualTo(clause.getParams().get(2));
        assertThat("%Knausen%").isEqualTo(clause.getParams().get(3));
    }

    @Test
    public void shouldReturnStandardQueryAndSplittedQueryForThreeNames(){
        String stdquery = getStdQuery();
        String splitnameQuery = getSingleSplitNameQuery();
        DbNameQuerier querier = getNameQuerier();
        String name = "Harald Knaus Knausen";
        WhereClause clause = querier.getQuery(name);
        assertEquals(stdquery + splitnameQuery + splitnameQuery, clause.getWherePart());
        assertThat("%Harald%").isEqualTo(clause.getParams().get(2));
        assertThat("%Knaus Knausen%").isEqualTo(clause.getParams().get(3));
        assertThat("%Harald Knaus%").isEqualTo(clause.getParams().get(4));
        assertThat("%Knausen%").isEqualTo(clause.getParams().get(5));
    }


    @Test
    public void shouldReturnStandardQueryAndSplittedQueryForFourNames(){
        String stdquery = getStdQuery();
        String splitnameQuery = getSingleSplitNameQuery();
        DbNameQuerier querier = getNameQuerier();
        String name = "Harald Jon Knaus Knausen";
        WhereClause clause = querier.getQuery(name);
        assertEquals(stdquery + splitnameQuery + splitnameQuery + splitnameQuery, clause.getWherePart());
        assertThat("%Harald%").isEqualTo(clause.getParams().get(2));
        assertThat("%Jon Knaus Knausen%").isEqualTo(clause.getParams().get(3));
        assertThat("%Harald Jon%").isEqualTo(clause.getParams().get(4));
        assertThat("%Knaus Knausen%").isEqualTo(clause.getParams().get(5));
        assertThat("%Harald Jon Knaus%").isEqualTo(clause.getParams().get(6));
        assertThat("%Knausen%").isEqualTo(clause.getParams().get(7));
    }


    private String getStdQuery() {
        return " (GivenName LIKE ? OR Surname LIKE ?)";
    }

    private String getSingleSplitNameQuery() {
        return " OR (GivenName LIKE ? AND Surname LIKE ?)";
    }

    private List<String> getStdParams(String name) {
        String[] params = {"%" + name + "%", "%" + name + "%"};
        return Arrays.asList(params);
    }


    private DbNameQuerier getNameQuerier() {
        return new DbNameQuerier();
    }

}
