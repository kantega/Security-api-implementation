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

import org.springframework.web.servlet.mvc.Controller;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * User: Anders Skar, Kantega AS
 * Date: Feb 17, 2007
 * Time: 6:26:20 PM
 */
public class ResetPasswordController implements Controller {
    public ModelAndView handleRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Hvordan bør dette virke ???
        // Skrive inn brukernavn: Får en epost med link med en hash ?
        // Klikk på linken

        

        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }
}
