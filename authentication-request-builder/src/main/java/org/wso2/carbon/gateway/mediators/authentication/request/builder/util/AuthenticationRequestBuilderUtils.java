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

package org.wso2.carbon.gateway.mediators.authentication.request.builder.util;

import java.net.URI;
import java.net.URISyntaxException;

public class AuthenticationRequestBuilderUtils {

    public static String buildAuthenticationEndpointURL(String url, String state, String callbackURL) throws
                                                                                              URISyntaxException {

        if (url == null || url.isEmpty()) {
            url = "http://localhost:8290/authenticate/";
        }

        if (state != null && !state.isEmpty()) {
            url = url + "?state=" + state;

        }
//        if (callbackURL != null) {
//            url = url + "&callbackurl=" + callbackURL;
//        }

//        URI uri = new URI(url);
        return url;
    }
}
