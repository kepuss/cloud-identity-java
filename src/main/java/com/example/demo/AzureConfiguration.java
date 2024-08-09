package com.example.demo;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.vault.authentication.AppRoleAuthentication;
import org.springframework.vault.authentication.AppRoleAuthenticationOptions;
import org.springframework.vault.authentication.ClientAuthentication;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.config.AbstractVaultConfiguration;

@Configuration(proxyBeanMethods = true)
public class AzureConfiguration extends AbstractVaultConfiguration {

    String vaultAuthnType = "approle";

    @Override
    public VaultEndpoint vaultEndpoint() {
        return VaultEndpoint.from(System.getenv("VAULT_URL"));
    }

    @Override
    public ClientAuthentication clientAuthentication() {
        switch (vaultAuthnType) {
            case "approle":
                return getAppRoleClientAuthentication();
            case "azure":
                return azureCloudClientAuthentication();
            default:
                return getAppRoleClientAuthentication();
        }
    }

    public ClientAuthentication getAppRoleClientAuthentication() {
        String roleId = System.getenv("VAULT_ROLE_ID");
        String secretId = System.getenv("VAULT_SECRET_ID");
        AppRoleAuthenticationOptions options = AppRoleAuthenticationOptions.builder()
                .roleId(AppRoleAuthenticationOptions.RoleId.provided(roleId))
                .secretId(AppRoleAuthenticationOptions.SecretId.provided(secretId)).build();
        return new AppRoleAuthentication(options, restOperations());
    }

    public ClientAuthentication azureCloudClientAuthentication() {
        String role = System.getenv("VAULT_ROLE");
        if (role == null) {
            role = "test-role";
        }
        return new WebAppClientAuthentication(restOperations(), role);
    }
}
