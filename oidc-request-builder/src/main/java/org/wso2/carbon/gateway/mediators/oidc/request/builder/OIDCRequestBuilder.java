/*
*  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
*  WSO2 Inc. licenses this file to you under the Apache License,
*  Version 2.0 (the "License"); you may not use this file except
*  in compliance with the License.
*  You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied.  See the License for the
* specific language governing permissions and limitations
* under the License.
*/

package org.wso2.carbon.gateway.mediators.oidc.request.builder;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.gateway.core.config.ParameterHolder;
import org.wso2.carbon.gateway.core.flow.AbstractMediator;
import org.wso2.carbon.messaging.CarbonCallback;
import org.wso2.carbon.messaging.CarbonMessage;
import org.wso2.carbon.messaging.Constants;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Mediator Implementation
 */
public class OIDCRequestBuilder extends AbstractMediator {

    private static final Logger log = LoggerFactory.getLogger(OIDCRequestBuilder.class);
    private static final String PROPERTY_TOKEN_ENDPOINT = "tokenep";
    private static final String PROPERTY_CALLBACK_URL = "callbackurl";
    private static final String PROPERTY_CLIENT_ID = "clientid";
    private static final String PROPERTY_SCOPE = "scope";

    private String logMessage = "Message received at Sample Mediator";
    private Map<String, String> parameters = new HashMap<>();

    @Override
    public String getName() {
        return "OIDCRequestBuilder";
    }

    /**
     * Mediate the message.
     * <p/>
     * This is the execution point of the mediator.
     *
     * @param carbonMessage  MessageContext to be mediated
     * @param carbonCallback Callback which can be use to call the previous step
     * @return whether mediation is success or not
     */
    @Override
    public boolean receive(CarbonMessage carbonMessage, CarbonCallback carbonCallback) throws Exception {

        if (log.isDebugEnabled()) {
            log.info("Message received at " + getName());
        }

        ResponseType responseType = new ResponseType();
        responseType.add(OIDCResponseTypeValue.ID_TOKEN);
        //responseType.add(ResponseType.Value.TOKEN);

        Scope scope = Scope.parse(parameters.get(PROPERTY_SCOPE));

        String encodedClientID = parameters.get(PROPERTY_CLIENT_ID);
        String decodedClientID = new String(Base64.getDecoder().decode(encodedClientID.getBytes(
                StandardCharsets.UTF_8)));

        ClientID clientID = new ClientID(decodedClientID);
        String sessionID = (String) carbonMessage.getProperty("sessionID");

        if (sessionID == null || sessionID.isEmpty()) {
            log.error("No session details found.");
            return false;
        }

        State state = new State(sessionID);
        Nonce nonce = new Nonce();

        URI tokenEP = new URI(parameters.get(PROPERTY_TOKEN_ENDPOINT));
        URI callback = new URI(parameters.get(PROPERTY_CALLBACK_URL));

        AuthenticationRequest authenticationRequest = new AuthenticationRequest(tokenEP, responseType, scope,
                                                                                clientID, callback, state,
                                                                                nonce);
        carbonMessage.setProperty(Constants.HTTP_STATUS_CODE, 302);
        carbonMessage.setHeader("Location", authenticationRequest.toURI().toASCIIString());

        //TODO: FIGURE THI OUT!!
//      SAMLtoOIDCDSL.authenticationContextMap.put(sessionID, (AuthenticationContext) carbonMessage.
//              getProperty("authenticationContext"));

        carbonCallback.done(carbonMessage);
        return true;
    }

    /**
     * Set Parameters
     *
     * @param parameterHolder holder which contains key-value pairs of parameters
     */
    @Override
    public void setParameters(ParameterHolder parameterHolder) {

        String paramString = parameterHolder.getParameter("parameters").getValue();
        String[] paramArray = paramString.split(",");

        for (String param : paramArray) {
            String[] params = param.split("=", 2);
            if (params.length == 2) {
                parameters.put(params[0].trim(), params[1].trim());
            }
        }
    }


    /**
     * This is a sample mediator specific method
     */
    public void setLogMessage(String logMessage) {
        this.logMessage = logMessage;
    }


}
