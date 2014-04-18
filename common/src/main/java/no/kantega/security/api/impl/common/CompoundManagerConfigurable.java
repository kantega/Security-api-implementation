package no.kantega.security.api.impl.common;

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

import java.util.List;

/**
 * User: Anders Skar, Kantega AS
 * Date: Jun 7, 2007
 * Time: 10:32:40 AM
 */
public abstract class CompoundManagerConfigurable<T> {
    protected String domain;
    protected List<T> managers;

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public void setManagers(List<T> managers) {
        this.managers = managers;
    }
}
