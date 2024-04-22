package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Controller;
import org.springframework.vault.annotation.VaultPropertySource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController("/test")
@VaultPropertySource("secret/app")
public class DemoController {
    @Autowired
    Environment env;

    @GetMapping("/test")
    public String test() {
        return "user: " + env.getProperty("database.username") + ", password: " + env.getProperty("database.password");
    }
}
