# Identity Mediation Language (IML)

## Setting up the demo

1. Build carbon-gateway-framework - https://github.com/wso2/carbon-gateway-framework
2. Build product-integration-server - https://github.com/wso2/product-integration-server
3. Build the following packages under `identity-gateway-mediators` and copy the jars to `<iserver_home>/osgi/dropins`
  1. authentication-endpoint
  2. authentication-request-builder
  3. authentication-response-processor
  4. identity-bus-framework
  5. oidc-request-builder
  6. oidc-response-processor
  7. saml-request-processor
  8. saml-response-builder
  
4. Copy the dependencies from `dependencies` to `<iserver_home>/osgi/dropins/`
 
  ```
  commons-cli_1.2.0.wso2v1.jar
  commons-codec_1.4.0.wso2v1.jar
  commons-collections_3.2.2.wso2v1.jar
  commons-configuration_1.6.0.wso2v1.jar
  commons-dbcp_1.4.0.wso2v1.jar
  commons-fileupload_1.2.2.wso2v1.jar
  commons-httpclient_3.1.0.wso2v2.jar
  commons-io_2.0.0.wso2v2.jar
  commons-io_2.4.0.wso2v1.jar
  commons-lang_2.6.0.wso2v1.jar
  commons-primitives_1.0.0.wso2v1.jar
  commons_lang3_3.3.2_1.0.0.jar
  lang_tag_1.4_1.0.0.jar
  net.minidev.json-smart_1.3.0.jar
  nimbus-jose-jwt_2.26.1.wso2v3.jar
  oauth2_oidc_sdk_4.8_1.0.0.jar
  opensaml2_2.4.1.wso2v1.jar
  tomcat-servlet-api_7.0.59.wso2v1.jar
  wss4j_1.5.11.wso2v11.jar
  xercesImpl-2.8.1.wso2v2.jar
  ```

5. Copy authentication-endpoint.iflow and one of the 3 integration flows from `integration-flows/v2.0` to `<iserver_home>/deployment/integration-flows/`.
6. Refer `README.md` in `integration-flows/v2.0` for more details on setting up each sample(use-case) in detail.

## Usecases

### Usecase 1 - Local Authenticator

![Image of Usecase 1](https://github.com/omindu/iml-poc/blob/master/integration-flows/local.png)

### Usecase 2 - Multi-Step Authentication

![Image of Usecase 1](https://github.com/omindu/iml-poc/blob/master/integration-flows/multi-step.png)

### Usecase 3 - Multi-Step with Role Based Step Control

![Image of Usecase 1](https://github.com/omindu/iml-poc/blob/master/integration-flows/RBAC.png)




