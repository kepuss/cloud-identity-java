package com.example.demo;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.vault.VaultException;
import org.springframework.vault.authentication.*;
import org.springframework.vault.support.VaultResponse;
import org.springframework.vault.support.VaultToken;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestOperations;

import java.time.Duration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class WebAppClientAuthentication implements ClientAuthentication {

    Logger logger = LoggerFactory.getLogger(WebAppClientAuthentication.class);
    RestOperations restOperations;

    String role;

    public WebAppClientAuthentication(RestOperations restOperations, String role) {
        this.role = role;
        this.restOperations = restOperations;
    }


    @Override
    public VaultToken login() throws VaultException {
        return this.createTokenUsingAzureMsiCompute();
    }

    private String getAccessToken() {
        String identityHeader = System.getenv("IDENTITY_HEADER");
        String identityEndpoint = System.getenv("IDENTITY_ENDPOINT");
        String url = identityEndpoint + "/?resource=https://vault.azure.net&api-version=2019-08-01";
        HttpHeaders headers = new HttpHeaders();
        headers.add("x-identity-header", identityHeader);

        ResponseEntity<Map> response = this.restOperations.exchange(url, HttpMethod.GET, new HttpEntity(headers), Map.class);
        String accessToken = (String)((Map)response.getBody()).get("access_token");
        logger.info("Azure MSI Access token: " + accessToken);
        return accessToken;

//        String jwt = ".eyJhdWQiOiJodHRwczovL3ZhdWx0LmF6dXJlLm5ldCIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzA1NDQwYmNmLTE3N2MtNDE5ZC05OTQ4LTgyOTdmNTk2NmFiNC8iLCJpYXQiOjE3MTM1MzQ1OTksIm5iZiI6MTcxMzUzNDU5OSwiZXhwIjoxNzEzNjIxMjk5LCJhaW8iOiJFMk5nWURCYU1WTnVvby85M3FicXhhVmFsc3N5QUE9PSIsImFwcGlkIjoiZjRlNzQyZGItZjU3Mi00NTYyLTg0MjMtZTQ0MGE5ODZmMDlhIiwiYXBwaWRhY3IiOiIyIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMDU0NDBiY2YtMTc3Yy00MTlkLTk5NDgtODI5N2Y1OTY2YWI0LyIsIm9pZCI6Ijk0MTBkMWM5LWViMDYtNDE0YS05NTVmLTYyODFiNTAwYzBmNCIsInJoIjoiMC5BRUlBend0RUJYd1huVUdaU0lLWDlaWnF0RG16cU0taWdocEhvOGtQd0w1NlFKTkNBQUEuIiwic3ViIjoiOTQxMGQxYzktZWIwNi00MTRhLTk1NWYtNjI4MWI1MDBjMGY0IiwidGlkIjoiMDU0NDBiY2YtMTc3Yy00MTlkLTk5NDgtODI5N2Y1OTY2YWI0IiwidXRpIjoiX2lNU2RPS2JYRW0xN1ZOeUZMOHRBQSIsInZlciI6IjEuMCIsInhtc19taXJpZCI6Ii9zdWJzY3JpcHRpb25zLzUxZmJiZmFjLTAxZmMtNGNjZS05MWJmLWVjNDg2MGY4Y2M2MC9yZXNvdXJjZWdyb3Vwcy9kZXZzZWNvcHMvcHJvdmlkZXJzL01pY3Jvc29mdC5BcHAvY29udGFpbmVyQXBwcy92YXVsdCJ9.a75agVjRSc_sPo64mE1KMAR_LR27d2mt0_D1DAj3fMRA5fU6E63Z_pna0_jFdpkDrl9yqk2gNUUNoCLxPLgIewwAyTvy5IX2qVoDOdyTkIoScvEOAb7CMvyTVZZzbX_vNnIi_5tRd7YT38prEIcCDlBF43ORrkUP3VM6bEBK55zBkXfyIF5k2rnRCIHaYrTFtbgPlAxfd0S1WmjRrBc8GbGmaDDOyxgdDDmqkXlJ7uGlPNKLd77VlNt6atHLx99eYtqftNP2DdX5lRwMjSe34uedHyq61ft8wBH3wwXtPT3fjs1gw2NGtGpMvFay3_Wd-Tc5z4A1jPTr-IeioMZGYw";
//        DecodedJWT token = JWT.decode(jwt);
//        String resource =token.getClaim("xms_mirid").asString();

    }


    private VaultToken createTokenUsingAzureMsiCompute() {
        try {
            Map<String, String> login = getAzureLogin(this.role, this.getAccessToken());

            VaultResponse response = (VaultResponse)this.restOperations.postForObject(getLoginPath("azure"), login, VaultResponse.class, new Object[0]);
            Assert.state(response != null && response.getAuth() != null, "Auth field must not be null");
            if (logger.isDebugEnabled()) {
                logger.debug("Login successful using Azure authentication");
            }

            return getLoginToken(response.getAuth());
        } catch (RestClientException var3) {
            logger.error("Cannot login using Azure authentication", var3);
            throw VaultLoginException.create("Azure", var3);
        }
    }

    static LoginToken getLoginToken(Map<String, Object> auth) {
        Assert.notNull(auth, "Authentication must not be null");
        String token = (String)auth.get("client_token");
        return from(token.toCharArray(), auth);
    }

    static LoginToken from(char[] token, Map<String, ?> auth) {
        Assert.notNull(auth, "Authentication must not be null");
        Boolean renewable = (Boolean)auth.get("renewable");
        Number leaseDuration = (Number)auth.get("lease_duration");
        String accessor = (String)auth.get("accessor");
        String type = (String)auth.get("type");
        if (leaseDuration == null) {
            leaseDuration = (Number)auth.get("ttl");
        }

        if (type == null) {
            type = (String)auth.get("token_type");
        }

        LoginToken.LoginTokenBuilder builder = LoginToken.builder();
        builder.token(token);
        if (StringUtils.hasText(accessor)) {
            builder.accessor(accessor);
        }

        if (leaseDuration != null) {
            builder.leaseDuration(Duration.ofSeconds(leaseDuration.longValue()));
        }

        if (renewable != null) {
            builder.renewable(renewable);
        }

        if (StringUtils.hasText(type)) {
            builder.type(type);
        }

        return builder.build();
    }

    static String getLoginPath(String authMount) {
        return String.format("auth/%s/login", authMount);
    }

//    "xms_mirid": "/subscriptions/51fbbfac-01fc-4cce-91bf-ec4860f8cc60/resourcegroups/devsecops/providers/Microsoft.App/containerApps/vault",
    private static Map<String, String> getAzureLogin(String role, String jwt) {
        DecodedJWT token = JWT.decode(jwt);
        String resource_id =token.getClaim("xms_mirid").asString();
        String regex = "/subscriptions/([^/]+)/resourcegroups/([^/]+)/providers/[^/]+/([^/]+)";

        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(resource_id);
        String subscriptionId = matcher.group(1);
        String resourceGroupName = matcher.group(2);

        Map<String, String> loginBody = new LinkedHashMap();
        loginBody.put("role", role);
        loginBody.put("jwt", jwt);
        loginBody.put("subscription_id", subscriptionId);
        loginBody.put("resource_group_name", resourceGroupName);
        loginBody.put("resource_id", resource_id);
//        loginBody.put("resource_id", "/subscriptions/51fbbfac-01fc-4cce-91bf-ec4860f8cc60/resourceGroups/devsecops/providers/Microsoft.App/containerApps/vault");
//        loginBody.put("vm_name", vmEnvironment.getVmName());
//        loginBody.put("vmss_name", vmEnvironment.getVmScaleSetName());
        return loginBody;
    }
}
