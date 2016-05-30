package org.wso2.carbon.gateway.mediators.authentication.response.processor.util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

public class AuthenticationResponseProcessorUtils {
    public static String getAuthenticationEndpointURL(String state) {
        if (state == null || state.isEmpty()) {
            return "http://localhost:8290/authenticate/";
        } else {
            return "http://localhost:8290/authenticate/?state=" + state;
        }
    }


    private static Map<String, char[]> userMap = new HashMap<>();

    private static Map<String, ArrayList<String>> userRoleMap = new HashMap<>();

    public static Map<String, char[]> getUserMap() {
        return userMap;
    }

    public static Map<String, ArrayList<String>> getUserRoleMap() {
        return userRoleMap;
    }

    static {
        userMap.put("admin", new char[] {'a', 'd', 'm', 'i', 'n'});
        userMap.put("testuser", new char[] {'t', 'e', 's', 't', '1', '2', '3'});

        userRoleMap.put("admin", new ArrayList<String>() {
            {
                add("admin");
            }
        });
        userRoleMap.put("testuser", new ArrayList<String>() {
            {
                add("nonadmin");
            }
        });
    }

}
