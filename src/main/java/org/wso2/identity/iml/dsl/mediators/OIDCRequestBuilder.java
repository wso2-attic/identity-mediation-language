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

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.identity.iml.dsl.SAMLtoOIDCDSL;
import org.wso2.identity.iml.dsl.context.AuthenticationContext;
import org.wso2.carbon.ibus.mediation.cheetah.flow.AbstractMediator;
import org.wso2.carbon.messaging.CarbonCallback;
import org.wso2.carbon.messaging.CarbonMessage;
import org.wso2.carbon.messaging.Constants;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.UUID;

public class OIDCRequestBuilder extends AbstractMediator {

    private static final Log log = LogFactory.getLog(OIDCRequestBuilder.class);

    @Override
    public String getName() {
        return "OIDCRequestBuilder";
    }

    @Override
    public boolean receive(CarbonMessage carbonMessage, CarbonCallback carbonCallback) throws Exception {

        if (log.isDebugEnabled()) {
            log.info("Message received at " + getName());
        }

        ResponseType responseType = new ResponseType();
        responseType.add(OIDCResponseTypeValue.ID_TOKEN);

        com.nimbusds.oauth2.sdk.Scope scope = com.nimbusds.oauth2.sdk.Scope.parse("openid");
        ClientID clientID = new ClientID("IDgZzC5_BZpfbdrvzolZsZZdMGga");

        String sessionID = UUID.randomUUID().toString();

        State state;
        if (sessionID != null) {
            state = new State(sessionID);
        } else {
            state = new State();
        }

        Nonce nonce = new Nonce();

        URI tokenEP = new URI("https://localhost:9444/oauth2/authorize");
        URI callback = new URI("http://localhost:8280/sample/request");
        AuthenticationRequest authenticationRequest = new AuthenticationRequest(tokenEP, responseType, scope,
                                                                                clientID, callback, state,
                                                                                nonce);
        carbonMessage.setProperty(Constants.HTTP_STATUS_CODE, 302);
        carbonMessage.setHeader("Location", authenticationRequest.toURI().toASCIIString());

        SAMLtoOIDCDSL.authenticationContextMap.put(sessionID, (AuthenticationContext) carbonMessage.
                getProperty("authenticationContext"));

        carbonCallback.done(carbonMessage);
        return true;
    }
}
