package no.kantega.security.api.impl.fedag.controller;

import org.springframework.web.servlet.mvc.Controller;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.jdbc.core.JdbcTemplate;
import org.apache.log4j.Logger;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import no.kantega.security.api.impl.fedag.identity.IdentityResolverImpl;
import no.kantega.security.api.impl.fedag.database.DatabaseAccess;
import no.kantega.security.api.impl.fedag.config.Config;

import java.io.PrintWriter;

/**
 * User: stelin
 * Date: 21.nov.2006
 * Time: 12:51:36
 */
public class LogoutController implements Controller {
    private Logger logger = Logger.getLogger(getClass());
    private DatabaseAccess dbAccess;

    public ModelAndView handleRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String subjectNameId = request.getParameter(IdentityResolverImpl.SUBJECT_NAME_ID_PARAMETER_NAME);
        String sessionIndex = request.getParameter(IdentityResolverImpl.SESSION_INDEX_PARAMETER_NAME);

        PrintWriter out = new PrintWriter(response.getOutputStream());
        response.setStatus(200);

        if (subjectNameId==null || sessionIndex==null){
            String msg = "Missing parameters "+IdentityResolverImpl.SUBJECT_NAME_ID_PARAMETER_NAME+" or "+IdentityResolverImpl.SESSION_INDEX_PARAMETER_NAME+". ";
            logger.error(msg + "subjectNameId="+subjectNameId+" sessionIndex="+sessionIndex);
            out.write("status=ERROR;message=Missing parameters subjectNameId or sessionIndex");
        }
        else{
            if (dbAccess.deleteSession(subjectNameId, sessionIndex)){
                out.write("status=SUCCESS");
            }
            else{
                out.write("status=NOT_FOUND;message=Specified session not found or error deleting session.");
            }
        }
        out.close();
        return null;
    }

    public void setJdbcTemplate(JdbcTemplate jdbcTemplate) {
        dbAccess.setJdbcTemplate(jdbcTemplate);
    }


    public void setDbAccess(DatabaseAccess dbAccess) {
        this.dbAccess = dbAccess;
    }
}
