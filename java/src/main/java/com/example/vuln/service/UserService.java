package com.example.vuln.service;

import com.example.vuln.model.User;
import com.example.vuln.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    // VULNERABILITY: Mass assignment / unsafe object population
    public User createUserFromParams(String username, String password, String role, boolean admin) {
        User user = new User();
        user.setUsername(username);
        user.setPassword(password);
        user.setRole(role);
        user.setAdmin(admin); // VULNERABILITY: Client-controlled admin flag
        userRepository.createUserUnsafe(username, password, role);
        return user;
    }

    // VULNERABILITY: Verbose error messages / information disclosure
    public User findUserVerbose(String username) {
        try {
            return userRepository.findByUsernameUnsafe(username).get(0);
        } catch (Exception e) {
            throw new RuntimeException("Database query failed: " + e.getMessage() + " for user " + username);
        }
    }

    // VULNERABILITY: Path traversal
    public byte[] getProfilePicture(String filename) throws IOException {
        Path path = Paths.get("/var/app/uploads/" + filename);
        return Files.readAllBytes(path);
    }

    // VULNERABILITY: Path traversal via File
    public String readUserFile(String filename) throws IOException {
        File file = new File("/var/app/data/" + filename);
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append("\n");
            }
        }
        return sb.toString();
    }

    // VULNERABILITY: OS command injection
    public String pingHost(String host) throws IOException, InterruptedException {
        Process process = Runtime.getRuntime().exec("ping -c 1 " + host);
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line).append("\n");
        }
        process.waitFor();
        return sb.toString();
    }

    // VULNERABILITY: OS command injection via ProcessBuilder
    public String runCommand(String command) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder("bash", "-c", command);
        Process process = pb.start();
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line).append("\n");
        }
        process.waitFor();
        return sb.toString();
    }

    // VULNERABILITY: Server-Side Request Forgery (SSRF)
    public String fetchUrl(String urlString) throws IOException {
        URL url = new URL(urlString);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line).append("\n");
        }
        reader.close();
        return sb.toString();
    }

    // VULNERABILITY: Insecure deserialization
    @SuppressWarnings("unchecked")
    public Object deserialize(byte[] data) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();
    }

    // VULNERABILITY: No rate limiting / brute-force friendly
    public boolean authenticate(String username, String password) {
        List<User> users = userRepository.findByUsernameUnsafe(username);
        if (users.isEmpty()) {
            return false;
        }
        User user = users.get(0);
        return user.getPassword().equals(password);
    }

    // VULNERABILITY: Insecure password storage (plaintext comparison)
    public boolean verifyPasswordPlaintext(User user, String password) {
        return user.getPassword().equals(password);
    }

    // VULNERABILITY: Debug endpoint exposing internal state
    public String debugInfo() {
        return System.getProperty("java.class.path") + "\n" + System.getProperty("user.dir");
    }
}
