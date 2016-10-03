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

package org.wso2.carbon.gateway.mediators.saml.response.builder;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.saml2.core.impl.AudienceBuilder;
import org.opensaml.saml2.core.impl.AudienceRestrictionBuilder;
import org.opensaml.saml2.core.impl.AuthnContextBuilder;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml2.core.impl.AuthnRequestImpl;
import org.opensaml.saml2.core.impl.AuthnStatementBuilder;
import org.opensaml.saml2.core.impl.ConditionsBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.ResponseBuilder;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.SubjectBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationDataBuilder;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;
import org.wso2.carbon.gateway.core.config.ParameterHolder;
import org.wso2.carbon.gateway.core.flow.AbstractMediator;
import org.wso2.carbon.gateway.mediators.saml.response.builder.util.SAMLResponseBuilderUtils;
import org.wso2.carbon.messaging.CarbonCallback;
import org.wso2.carbon.messaging.CarbonMessage;
import org.wso2.carbon.messaging.Constants;
import org.wso2.carbon.messaging.DefaultCarbonMessage;
import org.wso2.identity.bus.framework.AuthenticationContext;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import javax.naming.ConfigurationException;


/**
 * Mediator Implementation
 */
public class SAMLResponseBuilder extends AbstractMediator {

    private static final Logger log = LoggerFactory.getLogger(SAMLResponseBuilder.class);
    private String logMessage = "Message received at Sample Mediator";   // Sample Mediator specific variable


    @Override
    public String getName() {
        return "SAMLResponseBuilder";
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
            log.info("Message received at " + getName());
        }

        String sessionID = (String) carbonMessage.getProperty("sessionID");

        AuthenticationContext authenticationContextMap = SAMLResponseBuilderDataHolder.getInstance()
                .getAuthenticationContext();
        Map<String, Object> authenticationContext = (Map<String, Object>)
                authenticationContextMap.getFromContext(sessionID);

        AuthnRequest authnRequest = (AuthnRequest) authenticationContext.get("samlRequest");

        String samlResponse = buildSAMLResponse(authnRequest, authenticationContext, carbonMessage);
        DefaultCarbonMessage message = new DefaultCarbonMessage();
        String response = SAMLResponseBuilderUtils.getHTMLResponseBody(samlResponse);
        message.setStringMessageBody(response);

        int contentLength = response.getBytes().length;

        Map<String, String> transportHeaders = new HashMap<>();
        transportHeaders.put(Constants.HTTP_CONNECTION, Constants.KEEP_ALIVE);
        transportHeaders.put(Constants.HTTP_CONTENT_ENCODING, Constants.GZIP);
        transportHeaders.put(Constants.HTTP_CONTENT_TYPE, "text/html");
        transportHeaders.put(Constants.HTTP_CONTENT_LENGTH, (String.valueOf(contentLength)));

        message.setHeaders(transportHeaders);

        message.setProperty(Constants.HTTP_STATUS_CODE, 200);
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
        logMessage = parameterHolder.getParameter("parameters").getValue();
    }


    /**
     * This is a sample mediator specific method
     */
    public void setLogMessage(String logMessage) {
        this.logMessage = logMessage;
    }


    private String buildSAMLResponse(AuthnRequest authnRequest, Map<String, Object> authenticationContext,
                                     CarbonMessage carbonMessage) throws
                                                                                             ConfigurationException,
                                                                                             ParseException {

        String destination = "http://localhost:8080/travelocity.com/home.jsp";

        Response response = new ResponseBuilder().buildObject();

        response.setIssuer(SAMLResponseBuilderUtils.getIssuer());
        response.setID(UUID.randomUUID().toString());
        String inResponseTo = authnRequest.getID();
        response.setInResponseTo(inResponseTo);
        response.setDestination(authnRequest.getAssertionConsumerServiceURL());

        Status status = new StatusBuilder().buildObject();
        StatusCode statCode = new StatusCodeBuilder().buildObject();

        statCode.setValue("urn:oasis:names:tc:SAML:2.0:status:Success");
        status.setStatusCode(statCode);

        response.setVersion(SAMLVersion.VERSION_20);

        DateTime issueInstant = new DateTime();
        DateTime notOnOrAfter = new DateTime(issueInstant.getMillis() + 100 * 60 * 1000);

        response.setIssueInstant(issueInstant);

        //Build assertion

        DateTime currentTime = new DateTime();
        Assertion assertion = new AssertionBuilder().buildObject();
        assertion.setID(UUID.randomUUID().toString());
        assertion.setVersion(SAMLVersion.VERSION_20);
        assertion.setIssuer(SAMLResponseBuilderUtils.getIssuer());
        assertion.setIssueInstant(currentTime);
        Subject subject = new SubjectBuilder().buildObject();

        NameID nameId = new NameIDBuilder().buildObject();
        //TODO Get NameID value from JWT

        Map<String, String> subjectMap = (Map<String, String>) authenticationContext.get("subject");
        Map.Entry<String,String> subjectEntry = subjectMap.entrySet().iterator().next();
        nameId.setValue(subjectEntry.getValue());
        nameId.setFormat(NameID.UNSPECIFIED);

        subject.setNameID(nameId);

        SubjectConfirmation subjectConfirmation = new SubjectConfirmationBuilder().buildObject();
        subjectConfirmation.setMethod("urn:oasis:names:tc:SAML:2.0:cm:bearer");

        SubjectConfirmationData subjectConfirmationData = new SubjectConfirmationDataBuilder().buildObject();
        subjectConfirmationData.setInResponseTo(inResponseTo);
        subjectConfirmationData.setNotBefore(notOnOrAfter);
        subjectConfirmationData.setRecipient(destination);

        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);

        assertion.setSubject(subject);

        AuthnStatement authnStatement = new AuthnStatementBuilder().buildObject();
        authnStatement.setAuthnInstant(new DateTime());

        AuthnContext authnContext = new AuthnContextBuilder().buildObject();

        AuthnContextClassRef authnContextClassRef = new AuthnContextClassRefBuilder().buildObject();
        authnContextClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);

        authnContext.setAuthnContextClassRef(authnContextClassRef);
        authnStatement.setAuthnContext(authnContext);
        authnStatement.setSessionIndex((String) carbonMessage.getProperty("sessionID"));

        assertion.getAuthnStatements().add(authnStatement);


        Map<String, String> claims = (Map<String, String>) authenticationContext.get("attributes");

        if (claims != null && !claims.isEmpty()) {

            AttributeStatement attributeStatement = new AttributeStatementBuilder().buildObject();
            for (Map.Entry<String, String> entry : claims.entrySet()) {

                Attribute attribute = new AttributeBuilder().buildObject();
                attribute.setNameFormat(Attribute.BASIC);
                attribute.setName(entry.getKey());

                XSStringBuilder stringBuilder = (XSStringBuilder) Configuration.getBuilderFactory().getBuilder
                        (XSString.TYPE_NAME);
                XSString stringValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
                stringValue.setValue(entry.getValue());
                attribute.getAttributeValues().add(stringValue);
                attributeStatement.getAttributes().add(attribute);
            }
            assertion.getAttributeStatements().add(attributeStatement);
        }

        Conditions conditions = new ConditionsBuilder().buildObject();
        conditions.setNotBefore(currentTime);
        conditions.setNotOnOrAfter(notOnOrAfter);

        AudienceRestriction audienceRestriction = new AudienceRestrictionBuilder().buildObject();
        Audience audience = new AudienceBuilder().buildObject();
        audience.setAudienceURI("travelocity.com");
        audienceRestriction.getAudiences().add(audience);

        //TODO Handle multiple audience


        conditions.getAudienceRestrictions().add(audienceRestriction);
        assertion.setConditions(conditions);

        boolean doSignAssertion = false;
        boolean doEncryptAssertion = false;
        boolean doSignResponse = false;

        if (doSignAssertion) {
            //TODO Assertion signing
        }

        if (doEncryptAssertion) {
            //TODO Assertion encrypting
        }

        if (doSignResponse) {
            //TODO Response signing
        }

        response.getAssertions().add(assertion);

        String samlResponse = marshall(response);
        String encodedResponse = Base64.getEncoder().encodeToString(samlResponse.getBytes(StandardCharsets.UTF_8));
        return encodedResponse;

    }


    private String marshall(XMLObject xmlObject) throws ConfigurationException {

        SAMLResponseBuilderUtils.doBootstrap();

        try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
            System.setProperty("javax.xml.parsers.DocumentBuilderFactory", "org.apache.xerces.jaxp" +
                                                                           ".DocumentBuilderFactoryImpl");
            MarshallerFactory marshallerFactory = org.opensaml.xml.Configuration.getMarshallerFactory();
            Marshaller marshaller = marshallerFactory.getMarshaller(xmlObject);
            Element element = marshaller.marshall(xmlObject);

            DOMImplementationRegistry registry = DOMImplementationRegistry.newInstance();
            DOMImplementationLS impl = (DOMImplementationLS) registry.getDOMImplementation("LS");

            LSSerializer serializer = impl.createLSSerializer();
            LSOutput output = impl.createLSOutput();

            output.setByteStream(byteArrayOutputStream);
            serializer.write(element, output);

            return byteArrayOutputStream.toString(StandardCharsets.UTF_8.name());

        } catch (MarshallingException | IOException | ClassNotFoundException | InstantiationException |
                IllegalAccessException e) {
            //TODO Build SAML Error Resp and do proper logging
            log.error("Error while marshalling the SAML response", e);
            return null;
        }
    }
}
