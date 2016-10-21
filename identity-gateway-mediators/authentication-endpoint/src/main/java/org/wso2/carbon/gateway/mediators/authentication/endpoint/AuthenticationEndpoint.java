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

import static org.wso2.carbon.gateway.core.Constants.GZIP;
import static org.wso2.carbon.gateway.core.Constants.HTTP_CONNECTION;
import static org.wso2.carbon.gateway.core.Constants.HTTP_CONTENT_ENCODING;
import static org.wso2.carbon.gateway.core.Constants.HTTP_CONTENT_LENGTH;
import static org.wso2.carbon.gateway.core.Constants.HTTP_CONTENT_TYPE;
import static org.wso2.carbon.gateway.core.Constants.HTTP_STATUS_CODE;
import static org.wso2.carbon.gateway.core.Constants.KEEP_ALIVE;
import static org.wso2.carbon.gateway.core.Constants.MESSAGE_KEY;
import static org.wso2.carbon.gateway.core.Constants.RETURN_VALUE;
import static org.wso2.carbon.gateway.core.Constants.SERVICE_METHOD;


/**
 * Mediator Implementation
 */
public class AuthenticationEndpoint extends AbstractMediator {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationEndpoint.class);
    private static final String PROPERTY_CALLBAK_URL = "callbackurl";
    private String logMessage = "Message received at Authentication Endpoint";
    private Map<String, String> parameters = new HashMap<>();

    private static final Charset UTF_8 = StandardCharsets.UTF_8;
    private String messageRef;

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

        CarbonMessage inputCarbonMessage = (CarbonMessage) getObjectFromContext(carbonMessage, messageRef);
        if (inputCarbonMessage == null) {
            inputCarbonMessage = carbonMessage;
        }

        DefaultCarbonMessage authenticationResponseMessage;
        String callbackURL = parameters.get(PROPERTY_CALLBAK_URL);
        // state identifer
        String sessionID = "";

        if (inputCarbonMessage.getProperty(SERVICE_METHOD).equals("GET")) {

            Map<String, String> queryPairs = new HashMap<>();
            URI uri = new URI((String) inputCarbonMessage.getProperty(Constants.TO));
            String query = uri.getQuery();
            String[] pairs = query.split("&");

            for (String pair : pairs) {
                int idx = pair.indexOf("=");
                queryPairs.put(URLDecoder.decode(pair.substring(0, idx), UTF_8.name()),
                        URLDecoder.decode(pair.substring(idx + 1), UTF_8.name()));
            }

            sessionID = queryPairs.get("state");
            String encodedCallbackURL = queryPairs.get("callbackURL");

            if (encodedCallbackURL != null) {
                callbackURL = URLDecoder.decode(encodedCallbackURL, UTF_8.name());
            }

        } else if (carbonMessage.getProperty(SERVICE_METHOD).equals("POST")) {

            String contentLength = inputCarbonMessage.getHeader(HTTP_CONTENT_LENGTH);
            byte[] bytes = new byte[Integer.parseInt(contentLength)];

            List<ByteBuffer> fullMessageBody = inputCarbonMessage.getFullMessageBody();

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

            sessionID = paramsMap.get("state");

            /*
            // TODO: is this requestPath authentication?
            if ("admin".equals(paramsMap.get("username")) && "admin".equals(paramsMap.get("password"))) {

                authenticationResponseMessage = new DefaultCarbonMessage();
                String response = "";
                authenticationResponseMessage.setStringMessageBody(response);

                Map<String, String> transportHeaders = new HashMap<>();
                transportHeaders.put(HTTP_CONNECTION, KEEP_ALIVE);
                transportHeaders.put(HTTP_CONTENT_ENCODING, GZIP);
                transportHeaders.put(HTTP_CONTENT_TYPE, "text/html");
                transportHeaders.put(HTTP_CONTENT_LENGTH, (String.valueOf(response.getBytes(UTF_8).length)));

                authenticationResponseMessage.setHeaders(transportHeaders);
                authenticationResponseMessage.setProperty(HTTP_STATUS_CODE, 302);
                authenticationResponseMessage.setHeader("Location", AuthenticationEndpointUtils.getACSURL(state));
            } else {
                authenticationResponseMessage = getCarbonMessageWithLoginPage(callbackURL, state);
            }
            */
        } else {
            // Unsupported Method : throw exception and catch using NEL try-catch mediator
        }

        authenticationResponseMessage = getCarbonMessageWithLoginPage(callbackURL, sessionID);
        authenticationResponseMessage.setProperty(Constants.DIRECTION, Constants.DIRECTION_RESPONSE);
        authenticationResponseMessage.setProperty(Constants.CALL_BACK, carbonCallback);

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


    private DefaultCarbonMessage getCarbonMessageWithLoginPage(String callbackURL, String state) {

        DefaultCarbonMessage message = new DefaultCarbonMessage();
        String response = AuthenticationEndpointUtils.getLoginPage();

        response = response.replace("${state}", state);
        response = response.replace("${callbackURL}", callbackURL);
        message.setStringMessageBody(response);

        int contentLength = response.getBytes(UTF_8).length;

        Map<String, String> transportHeaders = new HashMap<>();
        transportHeaders.put(HTTP_CONNECTION, KEEP_ALIVE);
        transportHeaders.put(HTTP_CONTENT_ENCODING, GZIP);
        transportHeaders.put(HTTP_CONTENT_TYPE, "text/html");
        transportHeaders.put(HTTP_CONTENT_LENGTH, (String.valueOf(contentLength)));

        message.setHeaders(transportHeaders);
        message.setProperty(HTTP_STATUS_CODE, 200);
        return message;
    }
}
