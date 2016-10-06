/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.identity.iml.dsl.util;

import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.xml.ConfigurationException;

public class IMLUtils {

    private static boolean isBootStrapped = false;

    public static String getHTMLResponseBody(String samlResponse) {

        String responseBody = "<html>\n" +
                "\t<body>\n" +
                "        \t<p>You are now redirected to $url \n" +
                "        \tIf the redirection fails, please click the post button.</p>\n" +
                "        \t<form method='post' action='http://localhost:8080/travelocity.com/home.jsp'>\n" +
                "       \t\t\t<p>\n" +
                "<input type='hidden' name='SAMLResponse' value='" + samlResponse + "'>" +
                "        \t\t\t<button type='submit'>POST</button>\n" +
                "       \t\t\t</p>\n" +
                "       \t\t</form>\n" +
                "       \t\t<script type='text/javascript'>\n" +
                "        \t\tdocument.forms[0].submit();\n" +
                "        \t</script>\n" +
                "        </body>\n" +
                "</html>";

        return responseBody;
    }

    public static void doBootstrap() {
        if (!isBootStrapped) {
            try {
                DefaultBootstrap.bootstrap();
                isBootStrapped = true;
            } catch (ConfigurationException e) {
                e.printStackTrace();
                //log.error("Error in bootstrapping the OpenSAML2 library", e);
            }
        }
    }

    public static Issuer getIssuer() {
        Issuer issuer = new IssuerBuilder().buildObject();
        issuer.setValue("localhost");
        issuer.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:entity");

        return issuer;
    }

}
