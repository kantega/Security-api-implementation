/*
 * Copyright 2014 Kantega AS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package no.kantega.security.api.impl.twofactorauth.email;

import no.kantega.security.api.profile.Profile;
import no.kantega.security.api.twofactorauth.LoginToken;
import no.kantega.security.api.twofactorauth.LoginTokenSender;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Required;
import org.springframework.mail.MailSender;
import org.springframework.mail.SimpleMailMessage;

public class EmailLoginTokenSender implements LoginTokenSender {
    private final Logger log = LoggerFactory.getLogger(getClass());

    private MailSender mailSender;
    private String loginTokenEmailSubject;
    private String loginTokenEmailFrom;
    private String bodyText;

    @Override
    public void sendTokenToUser(Profile profile, LoginToken loginToken) {
        log.info("Sending LoginToken for user " + profile.getIdentity().getDomain() + ":" + profile.getIdentity().getUserId());
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(profile.getEmail());
        message.setSubject(loginTokenEmailSubject);
        message.setFrom(loginTokenEmailFrom);
        message.setText(bodyText.replace("{logintoken}", loginToken.getToken()));
        mailSender.send(message);
    }

    @Required
    public void setMailSender(MailSender mailSender) {
        this.mailSender = mailSender;
    }

    @Required
    public void setLoginTokenEmailSubject(String loginTokenEmailSubject) {
        this.loginTokenEmailSubject = loginTokenEmailSubject;
    }

    @Required
    public void setLoginTokenEmailFrom(String loginTokenEmailFrom) {
        this.loginTokenEmailFrom = loginTokenEmailFrom;
    }

    @Required
    public void setBodyText(String bodyText) {
        this.bodyText = bodyText;
    }
}
