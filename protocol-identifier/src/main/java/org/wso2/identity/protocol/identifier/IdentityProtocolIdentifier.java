package org.wso2.identity.protocol.identifier;

import org.wso2.carbon.ibus.mediation.cheetah.flow.AbstractMediator;
import org.wso2.carbon.messaging.CarbonCallback;
import org.wso2.carbon.messaging.CarbonMessage;

public class IdentityProtocolIdentifier extends AbstractMediator {

    @Override
    public String getName() {
        return "IdentityProtocolIdentifier";
    }

    @Override
    public boolean receive(CarbonMessage carbonMessage, CarbonCallback carbonCallback) throws Exception {
        return false;
    }
}
