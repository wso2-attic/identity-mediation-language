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

package org.wso2.carbon.identity.gateway.mediators.inbound.dispatcher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.gateway.core.Constants;
import org.wso2.carbon.gateway.core.config.Integration;
import org.wso2.carbon.gateway.core.config.IntegrationConfigRegistry;
import org.wso2.carbon.gateway.core.config.ParameterHolder;
import org.wso2.carbon.gateway.core.flow.AbstractMediator;
import org.wso2.carbon.gateway.core.flow.Resource;
import org.wso2.carbon.messaging.CarbonCallback;
import org.wso2.carbon.messaging.CarbonMessage;


/**
 * Simple Inbound Message Dispatcher Implementation.
 */
public class InboundMessageDispatcher extends AbstractMediator {

    private static final Logger log = LoggerFactory.getLogger(InboundMessageDispatcher.class);

    private String integrationKey;
    private String messageKey;
    /*
        Inbound resource to which we need to dispatch the received CarbonMessage to.
     */
    private String resourceName;

    private static final String RESOURCE_NAME = "resourceName";

    @Override
    public String getName() {
        return "InboundMessageDispatcher";
    }

    /**
     * Mediate the message.
     * <p>
     * This is the execution point of the mediator.
     *
     * @param carbonMessage  MessageContext to be mediated
     * @param carbonCallback Callback which can be use to call the previous step
     * @return whether mediation is success or not
     **/
    @Override
    public boolean receive(CarbonMessage carbonMessage, CarbonCallback carbonCallback) throws Exception {
        log.info("Invoking InboundMessageDispatcher Mediator");

        CarbonMessage inputCarbonMessage = (CarbonMessage) getObjectFromContext(carbonMessage, messageKey);
        if (inputCarbonMessage == null) {
            inputCarbonMessage = carbonMessage;
        }

        Integration currentIntegration = IntegrationConfigRegistry.getInstance().getIntegrationConfig(integrationKey);
        if (currentIntegration != null) {
            Resource inboundResource = currentIntegration.getResource(resourceName);
            if (inboundResource != null) {
                // dispatch the message to the resource inbound.
                return inboundResource.receive(inputCarbonMessage, carbonCallback);
            } else {
                log.error("Unable to find inbound resource " + resourceName + " to dispatch the message");
                return false;
            }
        } else {
            log.error("Unable to find an integration flow for key : " + integrationKey);
            // we can't come here for a valid integration. Just making the compiler happy.
            return false;
        }
    }

    /**
     * Set Parameters
     *
     * @param parameterHolder holder which contains key-value pairs of parameters
     */
    @Override
    public void setParameters(ParameterHolder parameterHolder) {
        // Read paremeters send as key value pairs here.
        messageKey = parameterHolder.getParameter(Constants.MESSAGE_KEY).getValue();
        integrationKey = parameterHolder.getParameter(Constants.INTEGRATION_KEY).getValue();
        resourceName = parameterHolder.getParameter(RESOURCE_NAME).getValue();
    }
}
