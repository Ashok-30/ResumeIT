package com.resumeit.resumeit_backend.controller;

import com.resumeit.resumeit_backend.model.User;
import com.resumeit.resumeit_backend.repository.UserRepository;
import com.resumeit.resumeit_backend.service.FileUploadService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping("/api/files")
@RequiredArgsConstructor
public class FileUploadController {

    private final FileUploadService fileUploadService;
    private final UserRepository userRepository;

    @PostMapping("/upload")
    public ResponseEntity<?> uploadResumes(@RequestParam("projectName") String projectName,
                                           @RequestParam("files") List<MultipartFile> files,
                                           @AuthenticationPrincipal(expression = "username") String email) throws IOException {
        User user = userRepository.findByEmailId(email).orElseThrow();
        fileUploadService.uploadFiles(user.getUserType(), projectName, files);
        return ResponseEntity.ok("Files uploaded successfully.");
    }
    @PostMapping("/upload-description")
    public ResponseEntity<?> uploadJobDescription(@RequestParam("projectName") String projectName,
                                                  @RequestParam("description") String description) throws IOException {
        fileUploadService.uploadJobDescription(projectName, description);
        return ResponseEntity.ok("Job description uploaded successfully.");
    }


}
