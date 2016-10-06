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

package org.wso2.carbon.gateway.mediators.authentication.response.processor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.gateway.core.config.ParameterHolder;
import org.wso2.carbon.gateway.core.flow.AbstractMediator;
import org.wso2.carbon.gateway.mediators.authentication.response.processor.util.AuthenticationResponseProcessorUtils;
import org.wso2.carbon.messaging.CarbonCallback;
import org.wso2.carbon.messaging.CarbonMessage;
import org.wso2.carbon.messaging.Constants;
import org.wso2.carbon.messaging.DefaultCarbonMessage;
import org.wso2.identity.bus.framework.AuthenticationContext;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;


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

        String contentLength = carbonMessage.getHeader(org.wso2.carbon.gateway.core.Constants.HTTP_CONTENT_LENGTH);
        byte[] bytes = new byte[Integer.parseInt(contentLength)];

        List<ByteBuffer> fullMessageBody = carbonMessage.getFullMessageBody();

        int offset = 0;

        for (ByteBuffer byteBuffer : fullMessageBody) {
            ByteBuffer duplicate = byteBuffer.duplicate();
            duplicate.get(bytes, offset, byteBuffer.capacity());
            offset = offset + duplicate.capacity();
        }

        DefaultCarbonMessage message = new DefaultCarbonMessage();
        message.setStringMessageBody("");

        String encodedParams = new String(bytes, UTF_8);
        String params = URLDecoder.decode(encodedParams, UTF_8.name());
        String[] paramsArray = params.split("&");

        Map<String, String> paramsMap = new HashMap<>();

        for (int i = 0; i < paramsArray.length; i++) {
            paramsMap.put(paramsArray[i].split("=")[0], paramsArray[i].split("=")[1]);
        }

        String state = paramsMap.get("state");
        message.setProperty("sessionID", state);

        String username = paramsMap.get("username");
        char[] passsword = paramsMap.get("password").toCharArray();

        if (Arrays.equals(AuthenticationResponseProcessorUtils.getUserMap().get(username), passsword)) {

            ArrayList<String> roles = AuthenticationResponseProcessorUtils.getUserRoleMap().get(username);
            String role = roles.get(0);
            message.setHeader("role", role);
            message.setHeader("isAuthenticated", "true");

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


            return next(message, carbonCallback);
        } else {
            String response = "";
            message.setStringMessageBody(response);
            message.setHeader("isAuthenticated", "false");

            Map<String, String> transportHeaders = new HashMap<>();
            transportHeaders.put(org.wso2.carbon.gateway.core.Constants.HTTP_CONNECTION,
                    org.wso2.carbon.gateway.core.Constants.KEEP_ALIVE);
            transportHeaders.put(org.wso2.carbon.gateway.core.Constants.HTTP_CONTENT_ENCODING,
                    org.wso2.carbon.gateway.core.Constants.GZIP);
            transportHeaders.put(org.wso2.carbon.gateway.core.Constants.HTTP_CONTENT_TYPE,
                    "text/html");
            transportHeaders.put(org.wso2.carbon.gateway.core.Constants.HTTP_CONTENT_LENGTH,
                    (String.valueOf(response.getBytes(UTF_8).length)));

            message.setHeaders(transportHeaders);
            message.setProperty(org.wso2.carbon.gateway.core.Constants.HTTP_STATUS_CODE, 302);

            URI uri = new URI(carbonMessage.getProperty(Constants.PROTOCOL).toString().toLowerCase(Locale.getDefault()),
                    null,
                    carbonMessage.getProperty(Constants.HOST).toString(),
                    Integer.parseInt(carbonMessage.getProperty(Constants.LISTENER_PORT).toString()),
                    carbonMessage.getProperty(Constants.TO).toString(),
                    null,
                    null);

            message.setHeader("Location", AuthenticationResponseProcessorUtils.
                    getAuthenticationEndpointURL(state, uri.toASCIIString()));
            message.setProperty(Constants.DIRECTION, Constants.DIRECTION_RESPONSE);
            message.setProperty(Constants.CALL_BACK, carbonCallback);
            carbonCallback.done(message);

            return true;
        }
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
