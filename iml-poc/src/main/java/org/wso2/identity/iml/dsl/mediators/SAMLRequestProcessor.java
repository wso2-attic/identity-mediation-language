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

package org.wso2.identity.iml.dsl.mediators;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xerces.util.SecurityManager;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.wso2.carbon.gateway.core.flow.AbstractMediator;
import org.wso2.carbon.messaging.CarbonCallback;
import org.wso2.carbon.messaging.CarbonMessage;
import org.wso2.carbon.messaging.Constants;
import org.wso2.carbon.messaging.DefaultCarbonMessage;
import org.wso2.identity.iml.dsl.context.AuthenticationContext;
import org.wso2.identity.iml.dsl.context.RequestContext;
import org.wso2.identity.iml.dsl.util.IMLUtils;
import org.xml.sax.SAXException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLDecoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

public class SAMLRequestProcessor extends AbstractMediator {

    private static final Log log = LogFactory.getLog(SAMLRequestProcessor.class);

    private static final String SECURITY_MANAGER_PROPERTY = org.apache.xerces.impl.Constants.XERCES_PROPERTY_PREFIX +
                                                            org.apache.xerces.impl.Constants.SECURITY_MANAGER_PROPERTY;
    @Override
    public String getName() {
        return "SAMLRequestProcessor";
    }

    @Override
    public boolean receive(CarbonMessage carbonMessage, CarbonCallback carbonCallback) throws Exception {


        if (log.isDebugEnabled()) {
            log.debug("Message received at " + getName());
        }

        CarbonMessage newReq;

        byte[] bytes;

        String contentLength = carbonMessage.getHeader(Constants.HTTP_CONTENT_LENGTH);
        if (contentLength != null) {

            newReq = new DefaultCarbonMessage();
            bytes = new byte[Integer.parseInt(contentLength)];

            newReq.setHeaders(carbonMessage.getHeaders());
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

            String encodedRequest = new String(bytes);
            String urlDecodedRequest = URLDecoder.decode(encodedRequest.split("=", 2)[1], StandardCharsets.UTF_8.name());
            String decodedRequest = new String(Base64.getDecoder().decode(urlDecodedRequest));

            if (log.isDebugEnabled()) {
                log.debug("Decoded SAML request: " + decodedRequest);
            }

            AuthnRequest samlAuthnRequest = SAMLRequestParser(decodedRequest);

            RequestContext samlRequestContext = new RequestContext();
            samlRequestContext.setHeaders(carbonMessage.getHeaders());
            samlRequestContext.addContent("samlRequest", samlAuthnRequest);

            AuthenticationContext authenticationContext = new AuthenticationContext();
            authenticationContext.getRequestContextMap().put("saml", samlRequestContext);

            newReq.setProperty("authenticationContext", authenticationContext);

        } else {
            newReq = carbonMessage;
        }
        return next(newReq, carbonCallback);
    }


    private AuthnRequest SAMLRequestParser(String samlRequest)
            throws ParserConfigurationException, SAXException, ConfigurationException, IOException,
                   UnmarshallingException {

        IMLUtils.doBootstrap();
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