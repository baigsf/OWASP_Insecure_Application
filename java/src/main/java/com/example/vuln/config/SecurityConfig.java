package com.example.vuln.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // VULNERABILITY: Disable CSRF protection
        http.csrf().disable()
            // VULNERABILITY: Permit all requests without authentication
            .authorizeRequests()
                .anyRequest().permitAll()
            .and()
            // VULNERABILITY: Disable security headers
            .headers()
                .frameOptions().disable()
                .xssProtection().disable()
                .contentTypeOptions().disable();
    }
}
