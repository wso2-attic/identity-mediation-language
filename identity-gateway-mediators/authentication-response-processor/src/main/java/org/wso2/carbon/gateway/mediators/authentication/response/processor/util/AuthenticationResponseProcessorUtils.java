package org.wso2.carbon.gateway.mediators.authentication.response.processor.util;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

/**
 * Util class for AuthenticationResponseProcessor
 */
public class AuthenticationResponseProcessorUtils {
    public static String getAuthenticationEndpointURL(String state, String callbackURL)
            throws UnsupportedEncodingException {
        if (state == null || state.isEmpty()) {
            return "http://localhost:8290/authenticate/";
        } else {
            return "http://localhost:8290/authenticate/?state=" + state + "&callbackurl=" +
                    URLEncoder.encode(callbackURL, StandardCharsets.UTF_8.name());
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
        userMap.put("admin", new char[]{'a', 'd', 'm', 'i', 'n'});
        userMap.put("omindu", new char[]{'t', 'e', 's', 't', '1', '2', '3'});

        userRoleMap.put("admin", new ArrayList<String>() {
            {
                add("admin");
            }
        });
        userRoleMap.put("omindu", new ArrayList<String>() {
            {
                add("nonadmin");
            }
        });
    }

}
