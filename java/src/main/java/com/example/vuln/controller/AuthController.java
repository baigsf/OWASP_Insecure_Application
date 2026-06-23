package com.example.vuln.controller;

import com.example.vuln.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

@RestController
public class AuthController {

    @Autowired
    private UserService userService;

    private static final String ADMIN_PASSWORD = "admin123";

    // VULNERABILITY: Hardcoded credentials
    @PostMapping("/admin/login")
    public String adminLogin(@RequestParam String password, HttpServletResponse response) {
        if (ADMIN_PASSWORD.equals(password)) {
            Cookie cookie = new Cookie("admin", "true");
            cookie.setHttpOnly(false);
            cookie.setSecure(false);
            response.addCookie(cookie);
            return "Welcome admin";
        }
        return "Invalid";
    }

    // VULNERABILITY: No rate limiting, weak authentication
    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password,
                        HttpServletResponse response) {
        if (userService.authenticate(username, password)) {
            Cookie session = new Cookie("session", username + ":" + System.currentTimeMillis());
            session.setHttpOnly(false);
            session.setSecure(false);
            response.addCookie(session);
            return "Logged in";
        }
        return "Invalid credentials";
    }

    // VULNERABILITY: Weak password hashing (MD5)
    @PostMapping("/register")
    public String register(@RequestParam String username, @RequestParam String password) throws NoSuchAlgorithmException {
        String hashed = md5(password);
        return "Registered " + username + " with hash " + hashed;
    }

    private String md5(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(input.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // VULNERABILITY: Session fixation / weak session management
    @PostMapping("/legacy/login")
    public String legacyLogin(@RequestParam String username, HttpServletResponse response) {
        Cookie cookie = new Cookie("JSESSIONID", username + "-session");
        cookie.setMaxAge(60 * 60 * 24 * 365);
        response.addCookie(cookie);
        return "OK";
    }

    // VULNERABILITY: Authentication bypass via parameter
    @GetMapping("/auth/check")
    public String checkAuth(@RequestParam(required = false) boolean bypass) {
        if (bypass) {
            return "Authenticated";
        }
        return "Not authenticated";
    }
}
