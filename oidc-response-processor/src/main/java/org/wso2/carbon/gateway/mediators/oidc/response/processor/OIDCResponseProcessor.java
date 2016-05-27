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

package org.wso2.carbon.gateway.mediators.oidc.response.processor;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.gateway.core.config.ParameterHolder;
import org.wso2.carbon.gateway.core.flow.AbstractMediator;
import org.wso2.carbon.messaging.CarbonCallback;
import org.wso2.carbon.messaging.CarbonMessage;
import org.wso2.carbon.messaging.Constants;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;


/**
* Mediator Implementation
*/
public class OIDCResponseProcessor extends AbstractMediator {

  private static final Logger log = LoggerFactory.getLogger(OIDCResponseProcessor.class);
  private String logMessage = "Message received at Sample Mediator";   // Sample Mediator specific variable


  @Override
  public String getName() {
    return "OIDCResponseProcessor";
  }

  /**
  * Mediate the message.
  *
  * This is the execution point of the mediator.
  * @param carbonMessage MessageContext to be mediated
  * @param carbonCallback Callback which can be use to call the previous step
  * @return whether mediation is success or not
  **/
  @Override
  public boolean receive(CarbonMessage carbonMessage, CarbonCallback carbonCallback) throws Exception {
      if (log.isDebugEnabled()) {
          log.debug("Message received at " + getName());
      }

      AuthenticationSuccessResponse successResponse = AuthenticationSuccessResponse.parse(new URI(
              (String) carbonMessage.getProperty(Constants.TO)));

      Map<String, String> query_pairs = new HashMap<>();
      URI uri = new URI((String) carbonMessage.getProperty(Constants.TO));
      String query = uri.getQuery();
      String[] pairs = query.split("&");

      for (String pair : pairs) {
          int idx = pair.indexOf("=");
          query_pairs.put(URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8.name()),
                          URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8.name()));
      }

      SignedJWT signedJWT = (SignedJWT) successResponse.getIDToken();

      //TODO JWT Sig validation

      String state = query_pairs.get("state");

      carbonMessage.setProperty("signedJWT", signedJWT);
      carbonMessage.setProperty("sessionID", state);

      return next(carbonMessage, carbonCallback);
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


  /** This is a sample mediator specific method */
  public void setLogMessage(String logMessage) {
     this.logMessage = logMessage;
  }


}
