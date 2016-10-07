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

package org.wso2.identity.bus.framework;


import java.util.HashMap;
import java.util.Map;

/**
 * AuthenticationContext Implementation to hold context information.
 */
public class AuthenticationContextImpl implements AuthenticationContext {

    private static Map<String, Object> authenticationContext = new HashMap<String, Object>();

    @Override
    public void addToContext(String key, Object value) {

        authenticationContext.put(key, value);
    }

    @Override
    public Object getFromContext(String key) {
        return authenticationContext.get(key);
    }
}
