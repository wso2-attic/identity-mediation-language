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

package org.wso2.carbon.identity.gateway.mediators.oidc.response.processor;

import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.gateway.core.config.ParameterHolder;
import org.wso2.carbon.gateway.core.flow.AbstractMediator;
import org.wso2.carbon.messaging.CarbonCallback;
import org.wso2.carbon.messaging.CarbonMessage;
import org.wso2.carbon.messaging.Constants;
import org.wso2.carbon.messaging.DefaultCarbonMessage;
import org.wso2.identity.bus.framework.AuthenticationContext;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
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
public class OIDCResponseProcessor extends AbstractMediator {

    private static final Logger log = LoggerFactory.getLogger(OIDCResponseProcessor.class);

    private static final String PROPERTY_IS_SUBJECT = "isSubject";
    private static final String PROPERTY_SUBJECT_CLAIM = "subjectClaim";
    private static final String PROPERTY_IS_ATTRIBUTE = "isAttribute";

    private static final Charset UTF_8 = StandardCharsets.UTF_8;

    private Map<String, String> parameters = new HashMap<>();
    private String messageRef;


    @Override
    public String getName() {
        return "OIDCResponseProcessor";
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

        log.info("Message Received at " + getName());

        CarbonMessage inputCarbonMessage = (CarbonMessage) getObjectFromContext(carbonMessage, messageRef);
        if (inputCarbonMessage == null) {
            inputCarbonMessage = carbonMessage;
        }

        AuthenticationSuccessResponse successResponse;
        DefaultCarbonMessage oidcResponseMessage = new DefaultCarbonMessage();
        String state;

        if (inputCarbonMessage.getProperty(SERVICE_METHOD).equals("GET")) {
            try {
                successResponse = AuthenticationSuccessResponse.parse(new URI((String) inputCarbonMessage.getProperty
                        (Constants.TO)));
                Map<String, String> queryPairMap = new HashMap<>();
                URI uri = new URI((String) inputCarbonMessage.getProperty(Constants.TO));
                String query = uri.getQuery();
                String[] pairs = query.split("&");

                for (String pair : pairs) {
                    int idx = pair.indexOf("=");
                    queryPairMap.put(URLDecoder.decode(pair.substring(0, idx), UTF_8.name()),
                            URLDecoder.decode(pair.substring(idx + 1), UTF_8.name()));
                }

                state = queryPairMap.get("state");

            } catch (ParseException e) {

                URI uri = new URI(
                        inputCarbonMessage.getProperty(Constants.PROTOCOL).toString().toLowerCase(Locale.getDefault()),
                        null,
                        inputCarbonMessage.getProperty(Constants.HOST).toString(),
                        Integer.parseInt(inputCarbonMessage.getProperty(Constants.LISTENER_PORT).toString()),
                        inputCarbonMessage.getProperty(Constants.TO).toString(),
                        null,
                        null);

                String response = getJavascript(uri.toASCIIString());
                oidcResponseMessage.setStringMessageBody(response);

                int contentLength = response.getBytes(UTF_8).length;

                Map<String, String> transportHeaders = new HashMap<>();
                transportHeaders.put(HTTP_CONNECTION, KEEP_ALIVE);
                transportHeaders.put(HTTP_CONTENT_ENCODING, GZIP);
                transportHeaders.put(HTTP_CONTENT_TYPE, "text/html");
                transportHeaders.put(HTTP_CONTENT_LENGTH, (String.valueOf(contentLength)));

                oidcResponseMessage.setHeaders(transportHeaders);
                // TODO : remove this
                oidcResponseMessage.setHeader("isOIDCResponse", "false");

                oidcResponseMessage.setProperty(HTTP_STATUS_CODE, 200);
                oidcResponseMessage.setProperty(Constants.DIRECTION, Constants.DIRECTION_RESPONSE);
                oidcResponseMessage.setProperty(Constants.CALL_BACK, carbonCallback);

                setObjectToContext(carbonMessage, getReturnedOutput(), oidcResponseMessage);
                return next(carbonMessage, carbonCallback);

            }
        } else if (inputCarbonMessage.getProperty(SERVICE_METHOD).equals("POST")) {

            String contentLength = inputCarbonMessage.getHeader(HTTP_CONTENT_LENGTH);
            byte[] bytes = new byte[Integer.parseInt(contentLength)];

            List<ByteBuffer> fullMessageBody = inputCarbonMessage.getFullMessageBody();

            int offset = 0;
            for (ByteBuffer byteBuffer : fullMessageBody) {
                ByteBuffer duplicate = byteBuffer.duplicate();
                duplicate.get(bytes, offset, byteBuffer.capacity());
                offset = offset + duplicate.capacity();
            }

            oidcResponseMessage.setStringMessageBody("");

            String encodedParams = new String(bytes, UTF_8);
            String fragment = URLDecoder.decode(encodedParams, UTF_8.name()).split("=", 2)[1];
            successResponse = AuthenticationSuccessResponse.parse(new URI(inputCarbonMessage.getProperty
                    (Constants.TO) + "#" + fragment));
            state = successResponse.getState().getValue();
        } else {
            // unsupported method.
            String serviceMethod = (String) inputCarbonMessage.getProperty(SERVICE_METHOD);
            log.error(serviceMethod + " not supported by the receive method of " + getName());
            return false;
        }

        SignedJWT signedJWT = (SignedJWT) successResponse.getIDToken();
        ReadOnlyJWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();

        //TODO JWT Sig validation

        AuthenticationContext authenticationContext = OIDCResponseProcessorDataHolder.getInstance()
                .getAuthenticationContext();
        if (Boolean.parseBoolean(parameters.get(PROPERTY_IS_SUBJECT))) {

            String subjectClaim = parameters.get(PROPERTY_SUBJECT_CLAIM);
            String subjectClaimValue;

            if (subjectClaim == null || subjectClaim.isEmpty()) {
                subjectClaimValue = jwtClaimsSet.getSubject();
            } else {
                subjectClaimValue = jwtClaimsSet.getStringClaim(subjectClaim);

                if (subjectClaimValue == null || subjectClaimValue.isEmpty()) {
                    subjectClaim = "sub";
                    subjectClaimValue = jwtClaimsSet.getSubject();
                }
            }

            Map<String, Object> responseContext = (Map<String, Object>) authenticationContext.getFromContext(state);

            final String finalSubjectClaim = subjectClaim;
            final String finalSubjectClaimValue = subjectClaimValue;

            Map<String, String> subjectClaimMap = new HashMap<>();
            subjectClaimMap.put(finalSubjectClaim, finalSubjectClaimValue);
            responseContext.put("subject", subjectClaimMap);

            authenticationContext.addToContext(state, responseContext);
        }

        if (Boolean.parseBoolean(parameters.get(PROPERTY_IS_ATTRIBUTE))) {
            Map<String, Object> responseContext = (Map<String, Object>) authenticationContext.getFromContext(state);

            Map<String, String> attributeMap = new HashMap<>();
            jwtClaimsSet.getCustomClaims().forEach((key, value) -> attributeMap.put(key, value.toString()));
            responseContext.put("attributes", attributeMap);

            authenticationContext.addToContext(state, responseContext);
        }

        oidcResponseMessage.setProperty("signedJWT", signedJWT);
        oidcResponseMessage.setProperty("sessionID", state);

        setObjectToContext(carbonMessage, getReturnedOutput(), oidcResponseMessage);
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

        // Get parameters sent as key=value from here.
        messageRef = parameterHolder.getParameter(MESSAGE_KEY).getValue();
        if (parameterHolder.getParameter(RETURN_VALUE) != null) {
            returnedOutput = parameterHolder.getParameter(RETURN_VALUE).getValue();
        }
    }

    private static String getJavascript(String callbackURL) {

        return "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3" +
                ".org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n" +
                "\n" +
                "<html>\n" +
                "    <head>\n" +
                "        <title></title>\n" +
                "    </head>\n" +
                "    <body>\n" +
                "        <p>You are now redirected to $url If the redirection fails, please click the " +
                "post button.</p>\n" +
                "        <form action='" + callbackURL + "' method='post'>\n" +
                "            <p><input name='fragment' id='id_token' type='hidden' value=''> <button " +
                "type='submit'>POST</button></p>\n" +
                "        </form>\n" +
                "        <script type='text/javascript'>\n" +
                "            document.getElementById('id_token').value = window.location.hash.substring" +
                "(1);\n" +
                "            document.forms[0].submit();\n" +
                "        </script>\n" +
                "    </body>\n" +
                "</html>";
    }
}
