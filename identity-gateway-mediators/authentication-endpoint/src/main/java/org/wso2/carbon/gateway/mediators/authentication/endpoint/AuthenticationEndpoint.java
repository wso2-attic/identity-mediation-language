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
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * Mediator Implementation
 */
public class AuthenticationEndpoint extends AbstractMediator {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationEndpoint.class);
    private static final String PROPERTY_CALLBAK_URL = "callbackurl";
    private String logMessage = "Message received at Authentication Endpoint";
    private Map<String, String> parameters = new HashMap<>();

    private static final Charset UTF_8 = StandardCharsets.UTF_8;

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
        String callbackURL = parameters.get(PROPERTY_CALLBAK_URL);

        if (carbonMessage.getProperty(org.wso2.carbon.gateway.core.Constants.SERVICE_METHOD).equals("GET")) {

            Map<String, String> queryPairs = new HashMap<>();
            URI uri = new URI((String) carbonMessage.getProperty(Constants.TO));
            String query = uri.getQuery();
            String[] pairs = query.split("&");

            for (String pair : pairs) {
                int idx = pair.indexOf("=");
                queryPairs.put(URLDecoder.decode(pair.substring(0, idx), UTF_8.name()),
                        URLDecoder.decode(pair.substring(idx + 1), UTF_8.name()));
            }

            String sessionID = queryPairs.get("state");
            String encodedCallbackURL = queryPairs.get("callbackURL");

            if (encodedCallbackURL != null) {
                callbackURL = URLDecoder.decode(encodedCallbackURL, UTF_8.name());
            }

            message = getCarbonMessageWithLoginPage(callbackURL, sessionID);

        } else if (carbonMessage.getProperty(org.wso2.carbon.gateway.core.Constants.SERVICE_METHOD).equals("POST")) {

            String contentLength = carbonMessage.getHeader(org.wso2.carbon.gateway.core.Constants.HTTP_CONTENT_LENGTH);
            byte[] bytes = new byte[Integer.parseInt(contentLength)];

            List<ByteBuffer> fullMessageBody = carbonMessage.getFullMessageBody();

            int offset = 0;

            for (ByteBuffer byteBuffer : fullMessageBody) {
                ByteBuffer duplicate = byteBuffer.duplicate();
                duplicate.get(bytes, offset, byteBuffer.capacity());
                offset = offset + duplicate.capacity();
            }

            String encodedParams = new String(bytes, UTF_8);
            String params = URLDecoder.decode(encodedParams, UTF_8.name());
            String[] paramsArray = params.split("&");

            Map<String, String> paramsMap = new HashMap<>();

            for (String aParamsArray : paramsArray) {
                paramsMap.put(aParamsArray.split("=")[0], aParamsArray.split("=")[1]);
            }

            String state = paramsMap.get("state");

            if ("admin".equals(paramsMap.get("username")) && "admin".equals(paramsMap.get("password"))) {

                message = new DefaultCarbonMessage();
                String response = "";
                message.setStringMessageBody(response);

                Map<String, String> transportHeaders = new HashMap<>();
                transportHeaders.put(org.wso2.carbon.gateway.core.Constants.HTTP_CONNECTION,
                        org.wso2.carbon.gateway.core.Constants.KEEP_ALIVE);
                transportHeaders.put(org.wso2.carbon.gateway.core.Constants.HTTP_CONTENT_ENCODING,
                        org.wso2.carbon.gateway.core.Constants.GZIP);
                transportHeaders.put(org.wso2.carbon.gateway.core.Constants.HTTP_CONTENT_TYPE, "text/html");
                transportHeaders.put(org.wso2.carbon.gateway.core.Constants.HTTP_CONTENT_LENGTH,
                        (String.valueOf(response.getBytes(UTF_8).length)));

                message.setHeaders(transportHeaders);
                message.setProperty(org.wso2.carbon.gateway.core.Constants.HTTP_STATUS_CODE, 302);
                message.setHeader("Location", AuthenticationEndpointUtils.getACSURL(state));
            } else {
                message = getCarbonMessageWithLoginPage(callbackURL, state);
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


    private DefaultCarbonMessage getCarbonMessageWithLoginPage(String callbackURL, String state) {

        DefaultCarbonMessage message = new DefaultCarbonMessage();
        String response = AuthenticationEndpointUtils.getLoginPage();

        response = response.replace("${state}", state);
        response = response.replace("${callbackURL}", callbackURL);
        message.setStringMessageBody(response);

        int contentLength = response.getBytes(UTF_8).length;

        Map<String, String> transportHeaders = new HashMap<>();
        transportHeaders.put(org.wso2.carbon.gateway.core.Constants.HTTP_CONNECTION,
                org.wso2.carbon.gateway.core.Constants.KEEP_ALIVE);
        transportHeaders.put(org.wso2.carbon.gateway.core.Constants.HTTP_CONTENT_ENCODING,
                org.wso2.carbon.gateway.core.Constants.GZIP);
        transportHeaders.put(org.wso2.carbon.gateway.core.Constants.HTTP_CONTENT_TYPE, "text/html");
        transportHeaders.put(org.wso2.carbon.gateway.core.Constants.HTTP_CONTENT_LENGTH,
                (String.valueOf(contentLength)));

        message.setHeaders(transportHeaders);

        message.setProperty(org.wso2.carbon.gateway.core.Constants.HTTP_STATUS_CODE, 200);
        return message;

    }
}
