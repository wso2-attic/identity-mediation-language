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

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
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
import org.wso2.carbon.messaging.DefaultCarbonMessage;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.gateway.core.Constants.HTTP_CONTENT_LENGTH;
import static org.wso2.carbon.gateway.core.Constants.HTTP_STATUS_CODE;
import static org.wso2.carbon.gateway.core.Constants.MESSAGE_KEY;
import static org.wso2.carbon.gateway.core.Constants.RETURN_VALUE;

/**
 * Mediator Implementation
 */
public class OIDCRequestBuilder extends AbstractMediator {

    private static final Logger log = LoggerFactory.getLogger(OIDCRequestBuilder.class);

    private static final String PROPERTY_TOKEN_ENDPOINT = "tokenEP";
    private static final String PROPERTY_AUTHZ_ENDPOINT = "authzEP";
    private static final String PROPERTY_CALLBACK_URL = "callbackURL";
    private static final String PROPERTY_CLIENT_ID = "clientID";
    private static final String PROPERTY_SCOPE = "scope";
    private static final String PROPERTY_REQUEST_TYPE = "requestType";

    private static final String AUTHORIZATION_HEADER = "Authorization";

    /*
        OIDC Request Types.
     */
    private static final String ID_TOKEN = OIDCResponseTypeValue.ID_TOKEN.getValue();
    private static final String TOKEN = ResponseType.Value.TOKEN.getValue();
    private static final String CODE = ResponseType.Value.CODE.getValue();

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

        DefaultCarbonMessage inputMessage = (DefaultCarbonMessage) getObjectFromContext(carbonMessage, messageRef);
        if (inputMessage == null) {
            inputMessage = (DefaultCarbonMessage) carbonMessage;
        }

        // request parameters
        String requestType = parameters.get(PROPERTY_REQUEST_TYPE);
        String encodedClientID = parameters.get(PROPERTY_CLIENT_ID);
        String scope = parameters.get(PROPERTY_SCOPE);

        // endpoints
        URI callback = new URI(parameters.get(PROPERTY_CALLBACK_URL));

        if (TOKEN.equals(requestType)) {
            URI tokenEP = new URI(parameters.get(PROPERTY_TOKEN_ENDPOINT));
            String authzCode = (String) inputMessage.getProperty("authorizationCode");
            String clientSecret = "";
            // build a token request
            TokenRequest tokenRequest = buildTokenRequest(authzCode, encodedClientID, clientSecret, callback, tokenEP);

            HTTPRequest tokenHttpRequest = tokenRequest.toHTTPRequest();

            String params = tokenHttpRequest.getQuery();
            int contentLength = params.getBytes(UTF_8).length;

            inputMessage.setHeader(AUTHORIZATION_HEADER, tokenHttpRequest.getAuthorization());

            inputMessage.setStringMessageBody(params);
            inputMessage.setHeader(HTTP_CONTENT_LENGTH, (String.valueOf(contentLength)));
            inputMessage.setProperty(HTTP_STATUS_CODE, 200);
            inputMessage.setProperty(Constants.DIRECTION, Constants.DIRECTION_RESPONSE);
            inputMessage.setProperty(Constants.CALL_BACK, carbonCallback);

        } else {
            URI authzEp = new URI(parameters.get(PROPERTY_AUTHZ_ENDPOINT));

            // if request type is empty we go with implicit flow
            if (requestType == null || requestType.isEmpty()) {
                requestType = ID_TOKEN;
            }

            String sessionID = (String) inputMessage.getProperty("sessionID");

            // build an authentication request.
            AuthenticationRequest authenticationRequest =
                    buildAuthenticationRequest(requestType, scope, encodedClientID, sessionID, authzEp, callback);

            inputMessage.setProperty(HTTP_STATUS_CODE, 302);
            inputMessage.setHeader("Location", authenticationRequest.toURI().toASCIIString());
        }

        setObjectToContext(carbonMessage, getReturnedOutput(), inputMessage);
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


    /*
        Build an OIDC authentication request.
     */
    private AuthenticationRequest buildAuthenticationRequest(String requestType,
                                                             String scope,
                                                             String encodedClientID,
                                                             String sessionID,
                                                             URI authorizationEndpoint,
                                                             URI callback) {
        ResponseType responseType = new ResponseType();
        // create response type based on param set in config
        if (CODE.equals(requestType)) {
            responseType.add(ResponseType.Value.CODE);
        } else {
            responseType.add(OIDCResponseTypeValue.ID_TOKEN);
        }

        // OIDC scope string
        Scope scopes = Scope.parse(scope);

        // ClientID
        String decodedClientID = new String(Base64.getDecoder().decode(encodedClientID.getBytes(UTF_8)), UTF_8);
        ClientID clientID = new ClientID(decodedClientID);

        if (sessionID == null || sessionID.isEmpty()) {
            log.error("Session ID not found in the message to build the OIDC request.");
            throw new IllegalArgumentException("Session ID cannot be empty.");
        }

        return new AuthenticationRequest.Builder(responseType, scopes, clientID, callback)
                .state(new State(sessionID))
                .nonce(new Nonce())
                .endpointURI(authorizationEndpoint)
                .build();
    }


    /*
        Build an OIDC token request using the authorization code sent by Authorization Server.
     */
    private TokenRequest buildTokenRequest(String authorizationCode,
                                           String encodedClientID,
                                           String clientSecret,
                                           URI callback,
                                           URI tokenEndpoint) throws URISyntaxException {

        AuthorizationCode code = new AuthorizationCode(authorizationCode);
        AuthorizationGrant codeGrant = new AuthorizationCodeGrant(code, callback);

        // ClientID
        String decodedClientID = new String(Base64.getDecoder().decode(encodedClientID.getBytes(UTF_8)), UTF_8);
        ClientID clientID = new ClientID(decodedClientID);

        // The credentials to authenticate the client at the token endpoint
        ClientAuthentication clientAuth = new ClientSecretBasic(clientID, new Secret(clientSecret));

        // Make the token request
        return new TokenRequest(tokenEndpoint, clientAuth, codeGrant);
    }

}
