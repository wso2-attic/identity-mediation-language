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

package org.wso2.carbon.gateway.mediators.authentication.endpoint;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.gateway.core.config.ParameterHolder;
import org.wso2.carbon.gateway.core.flow.AbstractMediator;
import org.wso2.carbon.gateway.mediators.authentication.endpoint.util.AuthenticationEndpointUtils;
import org.wso2.carbon.messaging.CarbonCallback;
import org.wso2.carbon.messaging.CarbonMessage;
import org.wso2.carbon.messaging.Constants;
import org.wso2.carbon.messaging.DefaultCarbonMessage;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * Mediator Implementation
 */
public class AuthenticationEndpoint extends AbstractMediator {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationEndpoint.class);
    private String logMessage = "Message received at Authentication Endpoint";

    @Override
    public String getName() {
        return "AuthenticationEndpoint";
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
        log.info("Invoking AuthenticationEndpoint Mediator");
        log.info(logMessage);

        DefaultCarbonMessage message = new DefaultCarbonMessage();

        if (carbonMessage.getProperty(org.wso2.carbon.gateway.core.Constants.SERVICE_METHOD).equals("GET")) {

            Map<String, String> queryPairs = new HashMap<>();
            URI uri = new URI((String) carbonMessage.getProperty(Constants.TO));
            String query = uri.getQuery();
            String[] pairs = query.split("&");

            for (String pair : pairs) {
                int idx = pair.indexOf("=");
                queryPairs.put(URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8.name()),
                               URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8.name()));
            }

            String sessionID = queryPairs.get("state");
            message = getCarbonMessageWithLoginPage(sessionID);

        } else if (carbonMessage.getProperty(org.wso2.carbon.gateway.core.Constants.SERVICE_METHOD).equals("POST")) {

            String contentLength = carbonMessage.getHeader(Constants.HTTP_CONTENT_LENGTH);
            byte[] bytes = new byte[Integer.parseInt(contentLength)];

            List<ByteBuffer> fullMessageBody = carbonMessage.getFullMessageBody();

            int offset = 0;

            for (ByteBuffer byteBuffer : fullMessageBody) {
                ByteBuffer duplicate = byteBuffer.duplicate();
                duplicate.get(bytes, offset, byteBuffer.capacity());
                offset = offset + duplicate.capacity();
            }

            String encodedParams = new String(bytes);
            String params = URLDecoder.decode(encodedParams, StandardCharsets.UTF_8.name());
            String[] paramsArray = params.split("&");

            Map<String, String> paramsMap = new HashMap<>();

            for (int i = 0; i < paramsArray.length; i++) {
                paramsMap.put(paramsArray[i].split("=")[0], paramsArray[i].split("=")[1]);
            }

            String state = paramsMap.get("state");

            if ("admin".equals(paramsMap.get("username")) && "admin".equals(paramsMap.get("password"))) {

                message = new DefaultCarbonMessage();
                String response = "";
                message.setStringMessageBody(response);

                Map<String, String> transportHeaders = new HashMap<>();
                transportHeaders.put(Constants.HTTP_CONNECTION, Constants.KEEP_ALIVE);
                transportHeaders.put(Constants.HTTP_CONTENT_ENCODING, Constants.GZIP);
                transportHeaders.put(Constants.HTTP_CONTENT_TYPE, "text/html");
                transportHeaders.put(Constants.HTTP_CONTENT_LENGTH, (String.valueOf(response.getBytes().length)));

                message.setHeaders(transportHeaders);
                message.setProperty(Constants.HTTP_STATUS_CODE, 302);
                message.setHeader("Location", AuthenticationEndpointUtils.getACSURL(state));
            } else {
                message = getCarbonMessageWithLoginPage(state);
            }

        }
        message.setProperty(Constants.DIRECTION, Constants.DIRECTION_RESPONSE);
        message.setProperty(Constants.CALL_BACK, carbonCallback);
        carbonCallback.done(message);

        return true;
    }

    /**
     * Set Parameters
     *
     * @param parameterHolder holder which contains key-value pairs of parameters
     */
    @Override
    public void setParameters(ParameterHolder parameterHolder) {
        logMessage = parameterHolder.getParameter("parameters").getValue();
    }


    /**
     * This is a sample mediator specific method
     */
    public void setLogMessage(String logMessage) {
        this.logMessage = logMessage;
    }


    private DefaultCarbonMessage getCarbonMessageWithLoginPage(String state) {

        DefaultCarbonMessage message = new DefaultCarbonMessage();
        String response = AuthenticationEndpointUtils.LOGIN_PAGE;

        response = response.replace("${state}", state);
        message.setStringMessageBody(response);

        int contentLength = response.getBytes().length;

        Map<String, String> transportHeaders = new HashMap<>();
        transportHeaders.put(Constants.HTTP_CONNECTION, Constants.KEEP_ALIVE);
        transportHeaders.put(Constants.HTTP_CONTENT_ENCODING, Constants.GZIP);
        transportHeaders.put(Constants.HTTP_CONTENT_TYPE, "text/html");
        transportHeaders.put(Constants.HTTP_CONTENT_LENGTH, (String.valueOf(contentLength)));

        message.setHeaders(transportHeaders);

        message.setProperty(Constants.HTTP_STATUS_CODE, 200);
        return message;

    }
}
