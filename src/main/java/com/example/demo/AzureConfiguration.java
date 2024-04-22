package com.example.demo;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.vault.authentication.AzureMsiAuthentication;
import org.springframework.vault.authentication.AzureMsiAuthenticationOptions;
import org.springframework.vault.authentication.ClientAuthentication;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.config.AbstractVaultConfiguration;

import java.net.URI;

@Configuration
public class AzureConfiguration extends AbstractVaultConfiguration {

    @Value("${VAULT_ROLE:test-role}")
    private String vaultRole;

    @Value("${VAULT_URL}")
    private String vaultUrl;

    @Override
    public VaultEndpoint vaultEndpoint() {
        return VaultEndpoint.from(vaultUrl);
    }

    @Override
    public ClientAuthentication clientAuthentication() {
        return new WebAppClientAuthentication(restOperations(), vaultRole);
    }
}
