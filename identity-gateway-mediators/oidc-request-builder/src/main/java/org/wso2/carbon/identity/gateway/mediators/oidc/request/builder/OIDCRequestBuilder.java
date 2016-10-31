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

package org.wso2.carbon.identity.gateway.mediators.oidc.request.builder;

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

import java.net.URI;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.gateway.core.Constants.HTTP_STATUS_CODE;
import static org.wso2.carbon.gateway.core.Constants.MESSAGE_KEY;
import static org.wso2.carbon.gateway.core.Constants.RETURN_VALUE;

/**
 * Mediator Implementation
 */
public class OIDCRequestBuilder extends AbstractMediator {

    private static final Logger log = LoggerFactory.getLogger(OIDCRequestBuilder.class);

    private static final String PROPERTY_TOKEN_ENDPOINT = "tokenep";
    private static final String PROPERTY_CALLBACK_URL = "callbackurl";
    private static final String PROPERTY_CLIENT_ID = "clientid";
    private static final String PROPERTY_SCOPE = "scope";
    private static final String PROPERTY_RESPONSE_TYPE = "responseType";

    private static final String ID_TOKEN = "id_token";
    private static final String CODE = "code";

    private static final Charset UTF_8 = StandardCharsets.UTF_8;

    private Map<String, String> parameters = new HashMap<>();
    private String messageRef;


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

        CarbonMessage inputCarbonMessage = (CarbonMessage) getObjectFromContext(carbonMessage, messageRef);
        if (inputCarbonMessage == null) {
            inputCarbonMessage = carbonMessage;
        }

        ResponseType responseType = new ResponseType();
        // create response type based on param set in config
        if (CODE.equals(parameters.get(PROPERTY_RESPONSE_TYPE))) {
            responseType.add(ResponseType.Value.CODE);
        } else {
            responseType.add(OIDCResponseTypeValue.ID_TOKEN);
        }

        // OIDC scope string
        Scope scope = Scope.parse(parameters.get(PROPERTY_SCOPE));

        String encodedClientID = parameters.get(PROPERTY_CLIENT_ID);
        String decodedClientID = new String(Base64.getDecoder().decode(encodedClientID.getBytes(UTF_8)), UTF_8);
        ClientID clientID = new ClientID(decodedClientID);

        String sessionID = (String) inputCarbonMessage.getProperty("sessionID");
        if (sessionID == null || sessionID.isEmpty()) {
            log.error("Session ID not found in the message to build the OIDC request.");
            return false;
        }

        State state = new State(sessionID);
        Nonce nonce = new Nonce();

        URI tokenEP = new URI(parameters.get(PROPERTY_TOKEN_ENDPOINT));
        URI callback = new URI(parameters.get(PROPERTY_CALLBACK_URL));

        AuthenticationRequest authenticationRequest = new AuthenticationRequest(tokenEP, responseType, scope, clientID,
                callback, state, nonce);

        inputCarbonMessage.setProperty(HTTP_STATUS_CODE, 302);
        inputCarbonMessage.setHeader("Location", authenticationRequest.toURI().toASCIIString());

        setObjectToContext(carbonMessage, getReturnedOutput(), inputCarbonMessage);
        return next(carbonMessage, carbonCallback);
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

        // Get parameters sent as key=value from here.
        messageRef = parameterHolder.getParameter(MESSAGE_KEY).getValue();
        if (parameterHolder.getParameter(RETURN_VALUE) != null) {
            returnedOutput = parameterHolder.getParameter(RETURN_VALUE).getValue();
        }
    }

}
