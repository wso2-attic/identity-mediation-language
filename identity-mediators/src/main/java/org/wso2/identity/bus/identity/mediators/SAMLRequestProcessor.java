package org.wso2.identity.bus.identity.mediators;

import org.wso2.carbon.ibus.mediation.cheetah.flow.AbstractMediator;
import org.wso2.carbon.messaging.CarbonCallback;
import org.wso2.carbon.messaging.CarbonMessage;
import org.wso2.carbon.messaging.Constants;
import org.wso2.carbon.messaging.DefaultCarbonMessage;

import java.net.URLDecoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

public class SAMLRequestProcessor extends AbstractMediator {
    @Override
    public String getName() {
        return null;
    }

    @Override
    public boolean receive(CarbonMessage carbonMessage, CarbonCallback carbonCallback) throws Exception {
        System.out.println("-My Custom Mediator-");

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
            System.out.println(decodedRequest);
            //SAMLRequestParser(decodedRequest);

        } else {
            newReq = carbonMessage;
        }
        return next(newReq, carbonCallback);

    }
}
