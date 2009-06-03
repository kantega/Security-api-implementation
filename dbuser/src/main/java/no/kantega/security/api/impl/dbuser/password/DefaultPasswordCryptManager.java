package no.kantega.security.api.impl.dbuser.password;

/*
 * Copyright 2009 Kantega AS
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.ApplicationContext;

import java.util.Map;

/**
 * Default implementation of PasswordCryptManager
 */
public class DefaultPasswordCryptManager implements PasswordCryptManager, ApplicationContextAware {

    private ApplicationContext applicationContext;

    public PasswordCrypt getPasswordCrypt(String id) {
        final Map<String, PasswordCrypt> map = applicationContext.getBeansOfType(PasswordCrypt.class);



        for(PasswordCrypt crypt : map.values()) {
            if(crypt.getId().equals(id)) {
                return crypt;
            }
        }

        final String defaultName = "defaultPasswordCrypt";

        if(!applicationContext.containsBean(defaultName)) {
            throw new IllegalStateException("No password crypts matched HashMech '" +id +"' and no bean 'defaultPasswordCrypt' is defined. Please configure appropriately");
        } else {
            PasswordCrypt defaultCrypt = (PasswordCrypt) applicationContext.getBean(defaultName, PasswordCrypt.class);

            return defaultCrypt;
        }
    }


    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }
}
