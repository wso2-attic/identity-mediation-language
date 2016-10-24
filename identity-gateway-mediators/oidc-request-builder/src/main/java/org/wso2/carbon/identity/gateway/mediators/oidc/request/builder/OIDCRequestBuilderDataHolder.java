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

package org.wso2.carbon.identity.gateway.inbound.dispatcher.mediators.oidc.request.builder;

import org.wso2.identity.bus.framework.AuthenticationContext;

/**
 * DataHolder for oidc-request-builder component.
 */
public class OIDCRequestBuilderDataHolder {
    private static OIDCRequestBuilderDataHolder instance = new OIDCRequestBuilderDataHolder();

    private AuthenticationContext authenticationContext;

    public static OIDCRequestBuilderDataHolder getInstance() {
        return instance;
    }

    public void setAuthenticationContextMap(AuthenticationContext authenticationContext) {
        this.authenticationContext = authenticationContext;
    }

    public AuthenticationContext getAuthenticationContext() {
        return authenticationContext;
    }

}