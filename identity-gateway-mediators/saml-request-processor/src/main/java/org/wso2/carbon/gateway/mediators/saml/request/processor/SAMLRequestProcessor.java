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

package org.wso2.carbon.gateway.mediators.saml.request.processor;

import org.apache.xerces.util.SecurityManager;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.wso2.carbon.gateway.core.config.ParameterHolder;
import org.wso2.carbon.gateway.core.flow.AbstractMediator;
import org.wso2.carbon.gateway.mediators.saml.request.processor.util.SAMLRequestProcessorUtils;
import org.wso2.carbon.messaging.CarbonCallback;
import org.wso2.carbon.messaging.CarbonMessage;
import org.wso2.carbon.messaging.DefaultCarbonMessage;
import org.wso2.identity.bus.framework.AuthenticationContext;
import org.xml.sax.SAXException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLDecoder;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;


/**
 * Mediator Implementation
 */
public class SAMLRequestProcessor extends AbstractMediator {

    private static final Logger log = LoggerFactory.getLogger(SAMLRequestProcessor.class);
    private String logMessage = "Message received at SAML Mediator";
    private static final String SECURITY_MANAGER_PROPERTY = org.apache.xerces.impl.Constants.XERCES_PROPERTY_PREFIX +
            org.apache.xerces.impl.Constants.SECURITY_MANAGER_PROPERTY;
    private static final Charset UTF_8 = StandardCharsets.UTF_8;

    @Override
    public String getName() {
        return "SAMLRequestProcessor";
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
        if (log.isDebugEnabled()) {
            log.debug("Message received at " + getName());
        }

        CarbonMessage newReq;

        byte[] bytes;

        String contentLength = carbonMessage.getHeader(org.wso2.carbon.gateway.core.Constants.HTTP_CONTENT_LENGTH);
        if (contentLength != null) {

            newReq = new DefaultCarbonMessage();
            bytes = new byte[Integer.parseInt(contentLength)];

            //  TODO fix this  newReq.setHeaders(carbonMessage.getHeaders());
            carbonMessage.getProperties().forEach(newReq::setProperty);
            List<ByteBuffer> fullMessageBody = carbonMessage.getFullMessageBody();

            int offset = 0;

            for (ByteBuffer byteBuffer : fullMessageBody) {
                newReq.addMessageBody(byteBuffer);
                ByteBuffer duplicate = byteBuffer.duplicate();
                duplicate.get(bytes, offset, byteBuffer.capacity());
                offset = offset + duplicate.capacity();
            }
            newReq.setEndOfMsgAdded(true);

            String encodedRequest = new String(bytes, UTF_8);
            String urlDecodedRequest = URLDecoder.decode(encodedRequest.split("=", 2)[1], UTF_8.name());
            String decodedRequest = new String(Base64.getDecoder().decode(urlDecodedRequest), UTF_8);

            if (log.isDebugEnabled()) {
                log.debug("Decoded SAML request: " + decodedRequest);
            }

            AuthnRequest samlAuthnRequest = buildSAMLRequest(decodedRequest);


            String sessionID = UUID.randomUUID().toString();
            Map<String, Object> requestContext = new HashMap<>();
            requestContext.put("samlRequest", samlAuthnRequest);


            AuthenticationContext authenticationContext = SAMLRequestProcessorDataHolder.getInstance()
                    .getAuthenticationContext();
            authenticationContext.addToContext(sessionID, requestContext);
            newReq.setProperty("sessionID", sessionID);

            //RequestContext samlRequestContext = new RequestContext();
            //samlRequestContext.setHeaders(carbonMessage.getHeaders());
            //samlRequestContext.addContent("samlRequest", samlAuthnRequest);

            //AuthenticationContext authenticationContext = new AuthenticationContext();
            //authenticationContext.getRequestContextMap().put("saml", samlRequestContext);

            //newReq.setProperty("authenticationContext", authenticationContext);

        } else {
            newReq = carbonMessage;
        }
        return next(newReq, carbonCallback);
    }

    /**
     * Set Parameters
     *
     * @param parameterHolder holder which contains key-value pairs of parameters
     */
    @Override
    public void setParameters(ParameterHolder parameterHolder) {
        // Get parameters sent as key=value from here.
    }


    /**
     * This is a sample mediator specific method
     */
    public void setLogMessage(String logMessage) {
        this.logMessage = logMessage;
    }


    private AuthnRequest buildSAMLRequest(String samlRequest)
            throws ParserConfigurationException, SAXException, ConfigurationException, IOException,
            UnmarshallingException {

        SAMLRequestProcessorUtils.doBootstrap();
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        documentBuilderFactory.setExpandEntityReferences(false);
        documentBuilderFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

        org.apache.xerces.util.SecurityManager securityManager = new SecurityManager();
        securityManager.setEntityExpansionLimit(0);

        documentBuilderFactory.setAttribute(SECURITY_MANAGER_PROPERTY, securityManager);
        DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
        docBuilder.setEntityResolver((publicId, systemId) -> {
            throw new SAXException("SAML request contains invalid elements. Possible XML External Entity " +
                    "(XXE) attack.");
        });

        try (InputStream inputStream = new ByteArrayInputStream(samlRequest.trim().getBytes(StandardCharsets
                .UTF_8))) {

            Document document = docBuilder.parse(inputStream);
            Element element = document.getDocumentElement();

            UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);

            AuthnRequest authnRequest = (AuthnRequest) unmarshaller.unmarshall(element);
            return authnRequest;
        }

    }
}
