package no.kantega.security.api.impl.common.password;

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

import no.kantega.security.api.password.PasswordManager;
import no.kantega.security.api.identity.Identity;
import no.kantega.security.api.common.SystemException;
import no.kantega.security.api.impl.common.CompoundManagerConfigurable;

/**
 * User: Anders Skar, Kantega AS
 * Date: Jun 7, 2007
 * Time: 10:25:57 AM
 */
public class CompoundPasswordManager extends CompoundManagerConfigurable implements PasswordManager {
    public boolean verifyPassword(Identity identity, String password) throws SystemException {
        for (int i = 0; i < managers.size(); i++) {
            PasswordManager pm = (PasswordManager)managers.get(i);
            if (identity.getDomain().equalsIgnoreCase(pm.getDomain())) {
                if (pm.verifyPassword(identity, password)) {
                    return true;
                }
            }
        }

        return false;
    }

    public void setPassword(Identity identity, String string, String string1) throws SystemException {

    }

    public boolean supportsPasswordChange() {
        return false;
    }

}
