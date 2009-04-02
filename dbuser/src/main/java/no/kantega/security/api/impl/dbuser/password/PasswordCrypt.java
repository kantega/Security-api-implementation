package no.kantega.security.api.impl.dbuser.password;

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

import java.security.NoSuchAlgorithmException;

/**
 * Author: Kristian Lier Seln�s, Kantega AS
 * Date: 27.mai.2008
 * Time: 13:30:08
 */
public interface PasswordCrypt {

    public String crypt(String password) throws NoSuchAlgorithmException;

    public String crypt(String password, String salt) throws NoSuchAlgorithmException;

}
