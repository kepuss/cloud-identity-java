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
        String url = identityEndpoint + "?resource=https://vault.azure.net&api-version=2019-08-01";
        HttpHeaders headers = new HttpHeaders();
        headers.add("x-identity-header", identityHeader);
        logger.info("Azure MSI URL: " + url);

        ResponseEntity<Map> response = this.restOperations.exchange(url, HttpMethod.GET, new HttpEntity(headers), Map.class);
        String accessToken = (String)((Map)response.getBody()).get("access_token");
        logger.info("Azure MSI Access token: " + accessToken);
        return accessToken;
    }


    private VaultToken createTokenUsingAzureMsiCompute() {
        try {
            Map<String, String> login = getAzureLogin(this.role, this.getAccessToken());
            logger.info("Trying to login using Azure authentication to vault: {}",System.getenv("VAULT_URL"));
            VaultResponse response = (VaultResponse)this.restOperations.postForObject(getLoginPath("azure"), login, VaultResponse.class, new Object[0]);
            Assert.state(response != null && response.getAuth() != null, "Auth field must not be null");
            logger.info("Login successful using Azure authentication");


            return getLoginToken(response.getAuth());
        } catch (Exception ex) {
            logger.error("Cannot login using Azure authentication", ex);
            throw VaultLoginException.create("Azure", ex);
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
        String subscriptionId = resource_id.split("/")[2];
        String resourceGroupName = resource_id.split("/")[4];

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
