package com.example.demo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Controller;
import org.springframework.vault.annotation.VaultPropertySource;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController("/test")
@VaultPropertySource("secret/app")
public class DemoController {
    @Autowired
    Environment env;

    @Autowired
    VaultTemplate vaultTemplate;

    @GetMapping("/test")
    public String test() {
        return "user: " + env.getProperty("database.username") + ", password: " + env.getProperty("database.password");
    }


    @PostMapping(value = "/saveSecret",consumes ="application/json")
    public JsonNode saveSecret(@RequestBody JsonNode secret) {
        vaultTemplate.write("secret/app/refreshToken", secret);
        return vaultTemplate.read("secret/app/refreshToken", JsonNode.class).getData();
    }
}
