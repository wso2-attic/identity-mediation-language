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

package org.wso2.carbon.identity.gateway.mediators.authentication.response.processor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.gateway.core.config.ParameterHolder;
import org.wso2.carbon.gateway.core.flow.AbstractMediator;
import org.wso2.carbon.identity.gateway.mediators.authentication.response.processor.util.AuthenticationResponseProcessorUtils;
import org.wso2.carbon.messaging.CarbonCallback;
import org.wso2.carbon.messaging.CarbonMessage;
import org.wso2.carbon.messaging.DefaultCarbonMessage;
import org.wso2.identity.bus.framework.AuthenticationContext;

import java.net.URLDecoder;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.gateway.core.Constants.HTTP_CONTENT_LENGTH;
import static org.wso2.carbon.gateway.core.Constants.MESSAGE_KEY;
import static org.wso2.carbon.gateway.core.Constants.RETURN_VALUE;


/**
 * Mediator Implementation
 */
public class AuthenticationResponseProcessor extends AbstractMediator {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationResponseProcessor.class);
    private static final String PROPERTY_IS_SUBJECT = "isSubject";
    private static final String PROPERTY_SUBJECT_CLAIM = "subjectClaim";
    private static final String PROPERTY_IS_ATTRIBUTE = "isAttribute";
    private String logMessage = "Message received at Sample Mediator";   // Sample Mediator specific variable
    private Map<String, String> parameters = new HashMap<>();

    private static final Charset UTF_8 = StandardCharsets.UTF_8;
    private String messageRef;

    @Override
    public String getName() {
        return "AuthenticationResponseProcessor";
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
        log.info("Invoking AuthenticationResponseProcessor Mediator");

        CarbonMessage inputCarbonMessage = (CarbonMessage) getObjectFromContext(carbonMessage, messageRef);
        if (inputCarbonMessage == null) {
            inputCarbonMessage = carbonMessage;
        }

        String contentLength = inputCarbonMessage.getHeader(HTTP_CONTENT_LENGTH);
        byte[] bytes = new byte[Integer.parseInt(contentLength)];

        List<ByteBuffer> fullMessageBody = carbonMessage.getFullMessageBody();

        int offset = 0;

        for (ByteBuffer byteBuffer : fullMessageBody) {
            ByteBuffer duplicate = byteBuffer.duplicate();
            duplicate.get(bytes, offset, byteBuffer.capacity());
            offset = offset + duplicate.capacity();
        }

        DefaultCarbonMessage authenticationResponseMessage = new DefaultCarbonMessage();
        authenticationResponseMessage.setStringMessageBody("");

        String encodedParams = new String(bytes, UTF_8);
        String params = URLDecoder.decode(encodedParams, UTF_8.name());
        String[] paramsArray = params.split("&");

        Map<String, String> paramsMap = new HashMap<>();

        for (int i = 0; i < paramsArray.length; i++) {
            String keyValue[] = paramsArray[i].split("=");
            String key = keyValue[0];
            String value = keyValue.length == 2 ? keyValue[1] : "";
            paramsMap.put(key, value);
        }

        String state = paramsMap.get("state");
        authenticationResponseMessage.setProperty("sessionID", state);

        String username = paramsMap.get("username");
        char[] passsword = paramsMap.get("password").toCharArray();

        if (Arrays.equals(AuthenticationResponseProcessorUtils.getUserMap().get(username), passsword)) {

            ArrayList<String> roles = AuthenticationResponseProcessorUtils.getUserRoleMap().get(username);
            String role = roles.get(0);
            authenticationResponseMessage.setHeader("role", role);
            authenticationResponseMessage.setHeader("isAuthenticated", "true");

            // TODO : remove this after filter mediator is corrected, as of now the filter mediator simply looks at the
            // carbon message passed to receive method instead of the actual message passed as a variable to it.
            carbonMessage.setHeader("role", role);
            carbonMessage.setHeader("isAuthenticated", "true");

            AuthenticationContext authenticationContext = AuthenticationResponseProcessorDataHolder.getInstance()
                    .getAuthenticationContext();

            if (Boolean.parseBoolean(parameters.get(PROPERTY_IS_SUBJECT))) {
                Map<String, Object> responseContext = (Map<String, Object>) authenticationContext.getFromContext(state);

                Map<String, String> subjectMap = new HashMap<>();
                subjectMap.put("username", username);
                responseContext.put("subject", subjectMap);

                authenticationContext.addToContext(state, responseContext);
            }

            if (Boolean.parseBoolean(parameters.get(PROPERTY_IS_ATTRIBUTE))) {
                Map<String, Object> responseContext = (Map<String, Object>) authenticationContext.getFromContext(state);

                Map<String, String> roleMap = new HashMap<>();
                roleMap.put("role", role);
                responseContext.put("attributes", roleMap);

                authenticationContext.addToContext(state, responseContext);
            }

            // set result of mediation to context

        } else {
            // If authentication fails, redirect again to the login page.
            String response = "";
            authenticationResponseMessage.setStringMessageBody(response);
            authenticationResponseMessage.setHeader("isAuthenticated", "false");

            // TODO : remove this after filter mediator is corrected, as of now the filter mediator simply looks at the
            // carbon message passed to receive method instead of the actual message passed as a variable to it.
            carbonMessage.setHeader("isAuthenticated", "false");

            // TODO : set anything else that is useful for the authentication request builder other mediators.
//            Map<String, String> transportHeaders = new HashMap<>();
//            transportHeaders.put(HTTP_CONNECTION, KEEP_ALIVE);
//            transportHeaders.put(HTTP_CONTENT_ENCODING, GZIP);
//            transportHeaders.put(HTTP_CONTENT_TYPE, "text/html");
//            transportHeaders.put(HTTP_CONTENT_LENGTH, (String.valueOf(response.getBytes(UTF_8).length)));
//
//            authenticationResponseMessage.setHeaders(transportHeaders);
//            authenticationResponseMessage.setProperty(HTTP_STATUS_CODE, 302);
//
//            URI uri = new URI(carbonMessage.getProperty(Constants.PROTOCOL).toString().
//                     toLowerCase(Locale.getDefault()),
//                    null,
//                    carbonMessage.getProperty(Constants.HOST).toString(),
//                    Integer.parseInt(carbonMessage.getProperty(Constants.LISTENER_PORT).toString()),
//                    carbonMessage.getProperty(Constants.TO).toString(),
//                    null,
//                    null);
//
//            authenticationResponseMessage.setHeader("Location", AuthenticationResponseProcessorUtils.
//                    getAuthenticationEndpointURL(state, uri.toASCIIString()));
//            authenticationResponseMessage.setProperty(Constants.DIRECTION, Constants.DIRECTION_RESPONSE);
//            authenticationResponseMessage.setProperty(Constants.CALL_BACK, carbonCallback);
//            carbonCallback.done(authenticationResponseMessage);
            //return true;
        }

        setObjectToContext(carbonMessage, getReturnedOutput(), authenticationResponseMessage);
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

        messageRef = parameterHolder.getParameter(MESSAGE_KEY).getValue();
        if (parameterHolder.getParameter(RETURN_VALUE) != null) {
            returnedOutput = parameterHolder.getParameter(RETURN_VALUE).getValue();
        }
    }


    /**
     * This is a sample mediator specific method
     */
    public void setLogMessage(String logMessage) {
        this.logMessage = logMessage;
    }


}
