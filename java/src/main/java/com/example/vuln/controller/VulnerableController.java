package com.example.vuln.controller;

import com.example.vuln.model.User;
import com.example.vuln.repository.UserRepository;
import com.example.vuln.service.UserService;
import com.example.vuln.service.XmlService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;

@RestController
public class VulnerableController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserService userService;

    @Autowired
    private XmlService xmlService;

    // VULNERABILITY: SQL Injection
    @GetMapping("/users/search")
    public List<User> searchUsers(@RequestParam String term) {
        return userRepository.searchUsersUnsafe(term);
    }

    // VULNERABILITY: SQL Injection
    @GetMapping("/users/{username}")
    public List<User> getUser(@PathVariable String username) {
        return userRepository.findByUsernameUnsafe(username);
    }

    // VULNERABILITY: SQL Injection
    @GetMapping("/users/order")
    public List<User> orderUsers(@RequestParam String column, @RequestParam String direction) {
        return userRepository.listUsersOrderedUnsafe(column, direction);
    }

    // VULNERABILITY: Reflected XSS
    @GetMapping("/greet")
    public void greet(@RequestParam String name, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>Hello " + name + "</body></html>");
    }

    // VULNERABILITY: Reflected XSS with inline JS
    @GetMapping("/welcome")
    public String welcome(@RequestParam String name) {
        return "<script>alert('Welcome " + name + "');</script>";
    }

    // VULNERABILITY: Stored XSS
    @PostMapping("/profile/html")
    public String storeProfileHtml(@RequestParam String username, @RequestParam String html) {
        List<User> users = userRepository.findByUsernameUnsafe(username);
        if (!users.isEmpty()) {
            User u = users.get(0);
            u.setProfileHtml(html);
            return "Saved";
        }
        return "Not found";
    }

    // VULNERABILITY: Stored XSS returned unsanitized
    @GetMapping("/profile/html")
    public String getProfileHtml(@RequestParam String username) {
        List<User> users = userRepository.findByUsernameUnsafe(username);
        if (!users.isEmpty()) {
            return users.get(0).getProfileHtml();
        }
        return "Not found";
    }

    // VULNERABILITY: OS Command Injection
    @GetMapping("/ping")
    public String ping(@RequestParam String host) throws Exception {
        return userService.pingHost(host);
    }

    // VULNERABILITY: Path Traversal
    @GetMapping("/file")
    public String readFile(@RequestParam String filename) throws Exception {
        return userService.readUserFile(filename);
    }

    // VULNERABILITY: SSRF
    @GetMapping("/fetch")
    public String fetch(@RequestParam String url) throws Exception {
        return userService.fetchUrl(url);
    }

    // VULNERABILITY: XXE
    @PostMapping("/xml")
    public String parseXml(@RequestBody String xml) throws Exception {
        return xmlService.parseXmlUnsafe(xml);
    }

    // VULNERABILITY: XPath injection
    @GetMapping("/xpath")
    public String xpath(@RequestParam String username) throws Exception {
        return xmlService.findUserByUsername(username);
    }

    // VULNERABILITY: Open redirect
    @GetMapping("/redirect")
    public void redirect(@RequestParam String url, HttpServletResponse response) throws IOException {
        response.sendRedirect(url);
    }

    // VULNERABILITY: Insecure deserialization
    @PostMapping("/deserialize")
    public String deserialize(@RequestBody String base64) throws Exception {
        userService.deserialize(java.util.Base64.getDecoder().decode(base64));
        return "Done";
    }

    // VULNERABILITY: CORS misconfiguration (allow all)
    @CrossOrigin(origins = "*")
    @GetMapping("/public/data")
    public String publicData() {
        return "sensitive data";
    }

    // VULNERABILITY: Missing authorization check
    @GetMapping("/admin/settings")
    public String adminSettings() {
        return "admin settings";
    }

    // VULNERABILITY: Insecure direct object reference
    @GetMapping("/account/{id}")
    public String accountById(@PathVariable Long id) {
        return "account " + id;
    }

    // VULNERABILITY: Log injection
    @GetMapping("/log")
    public String log(@RequestParam String msg, HttpServletRequest request) {
        System.out.println("User message: " + msg);
        return "logged";
    }
}
