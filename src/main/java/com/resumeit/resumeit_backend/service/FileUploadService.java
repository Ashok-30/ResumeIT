package com.resumeit.resumeit_backend.service;

import com.resumeit.resumeit_backend.model.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.*;
import java.util.List;

@Service
public class FileUploadService {

    @Value("${app.upload.base-path}")
    private String uploadBasePath;

    public void uploadFiles(User.UserType userType, String email, String projectName, List<MultipartFile> files) throws IOException {
        if (userType == User.UserType.RECRUITER && files.size() > 10) {
            throw new IllegalArgumentException("Recruiters can upload max 10 files.");
        }
        if (userType == User.UserType.JOB_SEEKER && files.size() > 1) {
            throw new IllegalArgumentException("Job seekers can upload only 1 file.");
        }

        Path projectDir = Paths.get(uploadBasePath, email, projectName);
        Files.createDirectories(projectDir);

        for (MultipartFile file : files) {
            Path filePath = projectDir.resolve(file.getOriginalFilename());
            file.transferTo(filePath);
        }
    }

    public void uploadJobDescription(String email, String projectName, String description) throws IOException {
        if (projectName == null || projectName.trim().isEmpty()) {
            throw new IllegalArgumentException("Project name cannot be empty.");
        }

        if (description == null || description.trim().isEmpty()) {
            throw new IllegalArgumentException("Job description cannot be empty.");
        }

        Path projectDir = Paths.get(uploadBasePath, email, projectName);
        Files.createDirectories(projectDir);

        Path descFile = projectDir.resolve("job_description.txt");
        Files.writeString(descFile, description, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
    }
}
