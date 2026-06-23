package com.example.vuln.controller;

import com.example.vuln.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

@RestController
public class ExtraVulnController {

    @Autowired
    private UserService userService;

    // VULNERABILITY: SQL Injection via Statement
    @GetMapping("/extra/user")
    public String extraUser(@RequestParam String name) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:vulndb", "sa", "sa");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE username = '" + name + "'");
        return rs.next() ? rs.getString("username") : "not found";
    }

    // VULNERABILITY: SQL Injection in batch
    @PostMapping("/extra/batch")
    public String extraBatch(@RequestParam String id) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:vulndb", "sa", "sa");
        Statement stmt = conn.createStatement();
        stmt.executeUpdate("DELETE FROM logs WHERE id = " + id);
        return "done";
    }

    // VULNERABILITY: Reflected XSS
    @GetMapping("/extra/greet")
    public void extraGreet(@RequestParam String name, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<div>Welcome " + name + "</div>");
    }

    // VULNERABILITY: Path traversal
    @GetMapping("/extra/read")
    public String extraRead(@RequestParam String path) throws IOException {
        return new String(Files.readAllBytes(Paths.get("/var/app/" + path)));
    }

    // VULNERABILITY: SSRF
    @GetMapping("/extra/proxy")
    public String extraProxy(@RequestParam String target) throws IOException {
        URL url = new URL(target);
        URLConnection conn = url.openConnection();
        return new String(conn.getInputStream().readAllBytes());
    }

    // VULNERABILITY: OS Command Injection
    @GetMapping("/extra/dns")
    public String extraDns(@RequestParam String host) throws Exception {
        return userService.runCommand("nslookup " + host);
    }

    // VULNERABILITY: Missing authorization
    @GetMapping("/extra/admin")
    public String extraAdmin() {
        return "admin-only data";
    }
}
