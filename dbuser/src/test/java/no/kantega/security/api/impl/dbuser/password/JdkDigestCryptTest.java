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

import org.junit.Test;

import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.assertEquals;

/**
 */
public class JdkDigestCryptTest {

    @Test
    public void testSha256() throws NoSuchAlgorithmException {
        JdkDigestCrypt crypt = new JdkDigestCrypt();
        crypt.setAlgorithm("SHA-256");

        assertEquals("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", crypt.crypt("password"));

    }

    @Test
    public void testM() throws NoSuchAlgorithmException {
        JdkDigestCrypt crypt = new JdkDigestCrypt();
        crypt.setAlgorithm("MD5");

        assertEquals("5f4dcc3b5aa765d61d8327deb882cf99", crypt.crypt("password"));

    }
}
