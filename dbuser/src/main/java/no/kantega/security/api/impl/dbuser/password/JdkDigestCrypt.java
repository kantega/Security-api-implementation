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
import java.security.MessageDigest;
import java.io.UnsupportedEncodingException;

/**
 * PasswordCrypt implementation using the JDK's MessageDigest API
 */
public class JdkDigestCrypt implements PasswordCrypt {

    private String algorithm;

    public String crypt(String password) throws NoSuchAlgorithmException {

        byte[] data = null;

        try {
            data = password.getBytes("utf-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("Encoding utf-8 not supported", e);
        }

        MessageDigest md = MessageDigest.getInstance(algorithm);
        md.update(data);
        final byte[] digest = md.digest();

        StringBuffer format = new StringBuffer();

        for (int i = 0; i < digest.length; i++) {
            int  b = ( (int)digest[i]) & 0xff;
            if(b < 16) {
                format.append("0");
            }
            format.append(Integer.toHexString(b).toLowerCase());

        }
        return format.toString();
    }

    public String crypt(String password, String salt) throws NoSuchAlgorithmException {
        return crypt(password);
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getId() {
        return algorithm;
    }
}
