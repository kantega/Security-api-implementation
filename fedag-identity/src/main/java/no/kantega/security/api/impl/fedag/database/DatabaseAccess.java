package no.kantega.security.api.impl.fedag.database;

import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.apache.log4j.Logger;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import no.kantega.security.api.identity.IdentificationFailedException;
import no.kantega.security.api.impl.fedag.config.Config;

/**
 * User: stelin
 * Date: 22.nov.2006
 * Time: 22:28:19
 */
public class DatabaseAccess {
    private JdbcTemplate jdbcTemplate;
    private Logger logger = Logger.getLogger(getClass());
    private Config config;

    /**
     *
     * @param subjectNameId
     * @param sessionIndex
     * @return true if delete was OK
     */
    public boolean deleteSession(String subjectNameId, String sessionIndex) {
        try {
            String sql = "delete from "+ config.getSessionTableName() +" WHERE saml_subjectNameId=? AND saml_sessionIndex=?";
            jdbcTemplate.update(sql , new Object[]{subjectNameId, sessionIndex});
            logger.info("Excecuting logout sql:"+sql + " subjectNameId=" + subjectNameId +  " sessionIndex="+sessionIndex);
            return true;
        } catch (DataAccessException e) {
            String msg = "Error deleting session from database. ";
            logger.error(msg + "subjectNameId="+subjectNameId+";sessionIndex="+sessionIndex);
            return false;
        }
    }

    public void insertSession(String subjectNameId, String sessionIndex, String sessionTablename) throws IdentificationFailedException {
        try {
            String sql = "INSERT INTO " + sessionTablename + " (saml_subjectNameId, saml_sessionIndex) VALUES (?,?)";
            jdbcTemplate.update(sql, new Object[]{subjectNameId, sessionIndex});
            logger.debug("Session stored in database: "+ sql + ", subjectNameId: "+ subjectNameId + " sessionIndex: "+ sessionIndex);
        } catch (DataAccessException e) {
            String msg = "Error creating session in database: ";
            logger.error(msg, e);
            throw new IdentificationFailedException("010", msg+e);
        }
    }

    public boolean checkSession(String subjectNameId, String sessionIndex, String sessionTablename) {
        try {
            int numSessions = jdbcTemplate.queryForInt("SELECT count(*) FROM " + sessionTablename + " WHERE saml_subjectNameId=? AND saml_sessionIndex=?", new Object[]{subjectNameId, sessionIndex});
            if (numSessions<1){
                String msg = "No session for this user in session database. Global logout has probably happened.";
                logger.info(msg);
                return false;
            }
        } catch (DataAccessException e) {
            String msg = "Failed validating session in database";
            logger.error(msg, e);
            return false;
        }
        return true;
    }

    public void setJdbcTemplate(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public void setConfig(Config config) {
        this.config = config;
    }
}
