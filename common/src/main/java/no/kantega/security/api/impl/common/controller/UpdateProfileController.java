package no.kantega.security.api.impl.common.controller;

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

import no.kantega.security.api.identity.DefaultIdentity;
import no.kantega.security.api.identity.Identity;
import no.kantega.security.api.identity.IdentityResolver;
import no.kantega.security.api.password.PasswordManager;
import no.kantega.security.api.profile.DefaultProfile;
import no.kantega.security.api.profile.Profile;
import no.kantega.security.api.profile.ProfileManager;
import no.kantega.security.api.profile.ProfileUpdateManager;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.Controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * User: Anders Skar, Kantega AS
 * Date: Feb 8, 2007
 * Time: 5:05:43 PM
 */
public class UpdateProfileController implements Controller {
    private ProfileManager profileManager = null;
    private ProfileUpdateManager profileUpdateManager = null;
    private PasswordManager passwordManager = null;
    private IdentityResolver identityResolver = null;
    private String domain;

    private String successView;
    private String editView;

    private final static String SURNAME_ATTR = "surname";
    private final static String GIVEN_NAME_ATTR = "givenName";
    private final static String EMAIL_ATTR = "email";
    private final static String DEPARTMENT_ATTR = "department";
    private final static String PASSWORD_ATTR = "password";
    private final static String PASSWORD2_ATTR = "password2";

    public ModelAndView handleRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {

        Profile existingProfile = null;

        Map<String, Object> model = new HashMap<>();

        Identity identity = identityResolver.getIdentity(request);
        if (identity != null) {
            // Bruker er logget inn, hent profil dersom finnes
            existingProfile = profileManager.getProfileForUser(identity);
        }

        model.put("passwordManager", passwordManager);

        if (request.getMethod().equalsIgnoreCase("POST")) {
            // Oppdater profil
            DefaultProfile profile = new DefaultProfile();

            boolean identityAlreadyInUse = false;
            if (existingProfile != null) {
                // Oppdater profil som finnes
                profile.setIdentity(identity);
                profile.setGivenName(existingProfile.getGivenName());
                profile.setSurname(existingProfile.getSurname());
                profile.setEmail(existingProfile.getEmail());
                profile.setDepartment(existingProfile.getDepartment());
                profile.setRawAttributes(existingProfile.getRawAttributes());
            } else {
                DefaultIdentity newIdentity = new DefaultIdentity();
                newIdentity.setDomain(domain);
                newIdentity.setUserId(request.getParameter("userid"));

                // Finnes profilen fra f�r ?
                if (profileManager.getProfileForUser(newIdentity) != null) {
                    identityAlreadyInUse = true;
                }
            }

            boolean passwordMismatch = false;
            String password1 = request.getParameter(PASSWORD_ATTR);
            String password2 = request.getParameter(PASSWORD2_ATTR);
            if (passwordManager != null && passwordManager.supportsPasswordChange() && password1 != null && password1.length() > 0) {
                if (!password1.equals(password2)) {
                    passwordMismatch = true;
                }
            }

            Enumeration paramNames = request.getParameterNames();

            profile.setSurname(request.getParameter(SURNAME_ATTR));
            profile.setGivenName(request.getParameter(GIVEN_NAME_ATTR));
            profile.setEmail(request.getParameter(EMAIL_ATTR));
            profile.setDepartment(request.getParameter(DEPARTMENT_ATTR));

            // Andre variabler lagres som identitet ...
            Properties props = new Properties();
            while (paramNames.hasMoreElements()) {
                String paramName = (String)paramNames.nextElement();
                if (!paramName.equals(SURNAME_ATTR) &&
                        !paramName.equals(GIVEN_NAME_ATTR) &&
                        !paramName.equals(EMAIL_ATTR) &&
                        !paramName.equals(PASSWORD_ATTR) &&
                        !paramName.equals(PASSWORD2_ATTR) &&
                        !paramName.equals(DEPARTMENT_ATTR)) {

                    String value = request.getParameter(paramName);
                    props.setProperty(paramName, value);

                }
            }

            profile.setRawAttributes(props);

            model.put("profile", profile);

            if (identityAlreadyInUse) {
                // Finnes fra f�r
                model.put("error", "IDENTITY_ALREADY_IN_USE");
                return new ModelAndView(editView, model);
            } else if (passwordMismatch) {
                // Finnes fra f�r
                model.put("error", "PASSWORD_MISMATCH");
                return new ModelAndView(editView, model);
            } else {
                // Lagre profil
                profileUpdateManager.saveOrUpdateProfile(profile);

                // Oppdater passord
                if (passwordManager != null && passwordManager.supportsPasswordChange() && password1 != null && password1.length() > 0) {
                    passwordManager.setPassword(profile.getIdentity(), password1, password2);
                }

                return new ModelAndView(successView, null);
            }
        } else {
            model.put("profile", existingProfile);
            return new ModelAndView(editView, model);
        }

    }

    public void setProfileManager(ProfileManager profileManager) {
        this.profileManager = profileManager;
    }

    public void setProfileUpdateManager(ProfileUpdateManager profileUpdateManager) {
        this.profileUpdateManager = profileUpdateManager;
    }

    public void setPasswordManager(PasswordManager passwordManager) {
        this.passwordManager = passwordManager;
    }

    public void setIdentityResolver(IdentityResolver identityResolver) {
        this.identityResolver = identityResolver;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public void setSuccessView(String successView) {
        this.successView = successView;
    }

    public void setEditView(String editView) {
        this.editView = editView;
    }
}
