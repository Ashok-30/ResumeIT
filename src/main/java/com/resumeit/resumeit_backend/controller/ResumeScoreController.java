package com.resumeit.resumeit_backend.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;


@RestController
@RequestMapping("/api")
public class ResumeScoreController {

    @Value("${file.upload-dir}")
    private String uploadDir;

    private final WebClient webClient = WebClient.create("http://localhost:8000");

    @PostMapping("/score-resumes")
    public ResponseEntity<?> scoreResumes(@RequestParam("projectName") String projectName,
                                          @AuthenticationPrincipal User principal) {

        String email = principal.getUsername();

        Path userProjectFolder = Paths.get("uploads", email, projectName);
        System.out.println("Resolved path: " + userProjectFolder.toAbsolutePath());
        System.out.println("Exists: " + Files.exists(userProjectFolder));


        File folder = userProjectFolder.toFile();

        if (!folder.exists() || !folder.isDirectory()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Project folder not found.");
        }

        // Get all files
        File[] files = folder.listFiles();
        if (files == null || files.length == 0) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("No files found in the folder.");
        }

        // Separate job description and resumes
        File jobDescFile = Arrays.stream(files)
                .filter(file -> file.getName().toLowerCase().contains("job"))
                .findFirst()
                .orElse(null);

        List<File> resumes = Arrays.stream(files)
                .filter(file -> !file.equals(jobDescFile))
                .toList();

        if (jobDescFile == null || resumes.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Missing job description or resumes.");
        }

        // Prepare request body
        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        body.add("job_description", new FileSystemResource(jobDescFile));
        resumes.forEach(resume -> body.add("resumes", new FileSystemResource(resume)));

        // Send request to Python API
        Mono<String> response = webClient.post()
                .uri("/score-resumes")
                .contentType(MediaType.MULTIPART_FORM_DATA)
                .bodyValue(body)
                .retrieve()
                .bodyToMono(String.class);

        // Return response to frontend
        String json = response.block();
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(json);
    }


    @PostMapping("/generate-questions")
    public ResponseEntity<?> generateQuestions(@RequestParam("projectName") String projectName,
                                               @AuthenticationPrincipal User principal) {

        String email = principal.getUsername();
        Path userProjectFolder = Paths.get("uploads", email, projectName);
        File folder = userProjectFolder.toFile();

        if (!folder.exists() || !folder.isDirectory()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Project folder not found.");
        }

        // Find job description and a single resume
        File jobDescFile = Arrays.stream(folder.listFiles())
                .filter(file -> file.getName().toLowerCase().contains("job"))
                .findFirst()
                .orElse(null);

        File resumeFile = Arrays.stream(folder.listFiles())
                .filter(file -> !file.equals(jobDescFile))
                .findFirst()
                .orElse(null);

        if (jobDescFile == null || resumeFile == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Missing job description or a resume.");
        }

        // Build request
        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        body.add("job_description", new FileSystemResource(jobDescFile));
        body.add("resume", new FileSystemResource(resumeFile));

        // Send to Flask
        Mono<String> response = webClient.post()
                .uri("/generate-questions")
                .contentType(MediaType.MULTIPART_FORM_DATA)
                .bodyValue(body)
                .retrieve()
                .bodyToMono(String.class);


        try {
            String json = response.block();
            System.out.println(">>> Flask Response: " + json);
            return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(json);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error calling Flask service: " + e.getMessage());
        }



    }



}
