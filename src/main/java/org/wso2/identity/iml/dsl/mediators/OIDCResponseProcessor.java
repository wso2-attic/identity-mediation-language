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

package org.wso2.identity.iml.dsl.mediators;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.ibus.mediation.cheetah.flow.AbstractMediator;
import org.wso2.carbon.messaging.CarbonCallback;
import org.wso2.carbon.messaging.CarbonMessage;
import org.wso2.carbon.messaging.Constants;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class OIDCResponseProcessor extends AbstractMediator {

    private static final Log log = LogFactory.getLog(OIDCResponseProcessor.class);

    @Override
    public String getName() {
        return "OIDCResponseProcessor";
    }

    @Override
    public boolean receive(CarbonMessage carbonMessage, CarbonCallback carbonCallback) throws Exception {

        if (log.isDebugEnabled()) {
            log.debug("Message received at " + getName());
        }

        AuthenticationSuccessResponse successResponse = AuthenticationSuccessResponse.parse(new URI(
                (String) carbonMessage.getProperty(Constants.TO)));

        Map<String, String> query_pairs = new HashMap<>();
        URI uri = new URI((String) carbonMessage.getProperty(Constants.TO));
        String query = uri.getQuery();
        String[] pairs = query.split("&");

        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            query_pairs.put(URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8.name()),
                            URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8.name()));
        }

        SignedJWT signedJWT = (SignedJWT) successResponse.getIDToken();

        //TODO JWT Sig validation

        String state = query_pairs.get("state");

        carbonMessage.setProperty("signedJWT", signedJWT);
        carbonMessage.setProperty("sessionID", state);

        return next(carbonMessage, carbonCallback);
    }
}