package com.example.demo;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.vault.authentication.AzureMsiAuthentication;
import org.springframework.vault.authentication.AzureMsiAuthenticationOptions;
import org.springframework.vault.authentication.ClientAuthentication;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.config.AbstractVaultConfiguration;

import java.net.URI;

@Configuration(proxyBeanMethods = true)
public class AzureConfiguration extends AbstractVaultConfiguration {


    @Override
    public VaultEndpoint vaultEndpoint() {
        return VaultEndpoint.from(System.getenv("VAULT_URL"));
    }

    @Override
    public ClientAuthentication clientAuthentication() {
        String role = System.getenv("VAULT_ROLE");
        if (role == null) {
            role = "test-role";
        }
        return new WebAppClientAuthentication(restOperations(), role);
    }
}
