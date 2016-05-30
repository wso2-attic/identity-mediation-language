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

package org.wso2.carbon.gateway.mediators.authentication.request.builder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.gateway.core.config.ParameterHolder;
import org.wso2.carbon.gateway.core.flow.AbstractMediator;
import org.wso2.carbon.gateway.mediators.authentication.request.builder.util.AuthenticationRequestBuilderUtils;
import org.wso2.carbon.messaging.CarbonCallback;
import org.wso2.carbon.messaging.CarbonMessage;
import org.wso2.carbon.messaging.Constants;
import org.wso2.carbon.messaging.DefaultCarbonMessage;

import java.util.HashMap;
import java.util.Map;


/**
 * Mediator Implementation
 */
public class AuthenticationRequestBuilder extends AbstractMediator {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationRequestBuilder.class);
    private static final String PROPERTY_AUTHENTICATION_ENDPOINT = "authep";
    private static final String PROPERTY_CALLBACK_URL = "calbackURL";
    private String logMessage = "Message received at Sample Mediator";   // Sample Mediator specific variable
    private Map<String, String> parameters = new HashMap<>();

    @Override
    public String getName() {
        return "AuthenticationRequestBuilder";
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
        log.info("Invoking AuthenticationRequestBuilder Mediator");

        DefaultCarbonMessage message = new DefaultCarbonMessage();
        String response = "";
        message.setStringMessageBody(response);

        String state = (String) carbonMessage.getProperty("sessionID");

        if (state == null || state.isEmpty()) {
            log.error("No session details found.");
            return false;
        }

        Map<String, String> transportHeaders = new HashMap<>();
        transportHeaders.put(Constants.HTTP_CONNECTION, Constants.KEEP_ALIVE);
        transportHeaders.put(Constants.HTTP_CONTENT_ENCODING, Constants.GZIP);
        transportHeaders.put(Constants.HTTP_CONTENT_TYPE, "text/html");
        transportHeaders.put(Constants.HTTP_CONTENT_LENGTH, (String.valueOf(response.getBytes().length)));

        message.setHeaders(transportHeaders);
        message.setProperty(Constants.HTTP_STATUS_CODE, 302);

        String authenticationEndpoint = parameters.get(PROPERTY_AUTHENTICATION_ENDPOINT);
        String callbackURL = parameters.get(PROPERTY_CALLBACK_URL);
        message.setHeader("Location", AuthenticationRequestBuilderUtils.buildAuthenticationEndpointURL
                (authenticationEndpoint, state, callbackURL));
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


}
