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

package org.wso2.carbon.identity.gateway.inbound.dispatcher.mediators.saml.request.processor;

import org.osgi.framework.BundleContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.gateway.core.flow.Mediator;
import org.wso2.carbon.gateway.core.flow.MediatorProvider;
import org.wso2.identity.bus.framework.AuthenticationContext;

import java.util.Map;

/**
 * Mediator Provider Implementation
 */
@Component(
        name = "SAMLRequestProcessorProvider",
        immediate = true,
        service = MediatorProvider.class
)
public class SAMLRequestProcessorProvider implements MediatorProvider {

    @Activate
    protected void start(BundleContext bundleContext) {
        bundleContext.getBundles();
    }

    @Reference(
            name = "AuthenticationContext",
            service = AuthenticationContext.class,
            cardinality = ReferenceCardinality.OPTIONAL,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unregister"

    )
    protected void register(AuthenticationContext authenticationContext, Map<String, String> properties) {
        SAMLRequestProcessorDataHolder.getInstance().setAuthenticationContextMap(authenticationContext);
    }

    protected void unregister(AuthenticationContext authenticationContext) {
    }

    @Override
    public String getName() {
        return "SAMLRequestProcessor";
    }

    @Override
    public Mediator getMediator() {
        return new SAMLRequestProcessor();
    }

}
