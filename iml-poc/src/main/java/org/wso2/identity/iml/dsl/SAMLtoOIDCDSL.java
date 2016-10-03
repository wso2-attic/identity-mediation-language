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

package org.wso2.identity.iml.dsl;


import org.wso2.carbon.gateway.core.config.dsl.internal.JavaConfigurationBuilder;
import org.wso2.identity.iml.dsl.context.AuthenticationContext;
import org.wso2.identity.iml.dsl.mediators.OIDCRequestBuilder;
import org.wso2.identity.iml.dsl.mediators.OIDCResponseProcessor;
import org.wso2.identity.iml.dsl.mediators.SAMLRequestProcessor;
import org.wso2.identity.iml.dsl.mediators.SAMLResponseBuilder;

import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.gateway.core.config.dsl.internal.flow.mediators.CustomMediatorBuilder.process;
import static org.wso2.carbon.gateway.core.config.dsl.internal.flow.mediators.FilterMediatorBuilder.pattern;
import static org.wso2.carbon.gateway.core.config.dsl.internal.flow.mediators.FilterMediatorBuilder.source;
import static org.wso2.carbon.gateway.inbounds.http.builder.HTTPInboundEPBuilder.context;
import static org.wso2.carbon.gateway.inbounds.http.builder.HTTPInboundEPBuilder.http;
import static org.wso2.carbon.gateway.inbounds.http.builder.HTTPInboundEPBuilder.port;


public class SAMLtoOIDCDSL extends JavaConfigurationBuilder {

    public static Map<String, AuthenticationContext> authenticationContextMap = new HashMap<>();

    public IntegrationFlow configure() {

        IntegrationFlow router = integrationFlow("MessageRouter");

        router.inboundEndpoint("inboundEndpoint1", http(port(8280), context("/sample/request"))).
                pipeline("pipeline1").
                filter(source("$header.Referer"), pattern(".*samlsso.*")).
                then(process(new SAMLRequestProcessor()).process(new OIDCRequestBuilder())).
                otherwise(process(new OIDCResponseProcessor()).process(new SAMLResponseBuilder())).
                respond();

        return router;

    }



}



