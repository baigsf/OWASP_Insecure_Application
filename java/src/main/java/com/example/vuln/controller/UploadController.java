package com.example.vuln.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@RestController
public class UploadController {

    private static final String UPLOAD_DIR = "/var/app/uploads/";

    // VULNERABILITY: Unrestricted file upload
    @PostMapping("/upload")
    public String upload(@RequestParam("file") MultipartFile file) throws IOException {
        Path path = Paths.get(UPLOAD_DIR + file.getOriginalFilename());
        Files.write(path, file.getBytes());
        return "Uploaded to " + path;
    }

    // VULNERABILITY: File upload without extension validation
    @PostMapping("/upload/avatar")
    public String uploadAvatar(@RequestParam("file") MultipartFile file, @RequestParam String name) throws IOException {
        File dest = new File(UPLOAD_DIR + name);
        file.transferTo(dest);
        return "Saved avatar";
    }

    // VULNERABILITY: Path traversal in download
    @GetMapping("/download")
    public byte[] download(@RequestParam String filename) throws IOException {
        return Files.readAllBytes(Paths.get(UPLOAD_DIR + filename));
    }
}
