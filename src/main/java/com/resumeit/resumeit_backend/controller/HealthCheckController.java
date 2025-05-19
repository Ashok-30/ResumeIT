package com.resumeit.resumeit_backend.controller;

import com.resumeit.resumeit_backend.model.Resume;
import com.resumeit.resumeit_backend.repository.ResumeRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("/api")
public class HealthCheckController {

    @Autowired
    private ResumeRepository resumeRepository;


    @GetMapping("/health")
    public String healthCheck() {
        Resume resume = new Resume();
        resume.setFullName("Test User");
        resume.setContent("Sample resume content");
        resumeRepository.save(resume);
        return "Hello, ResumeAI! Saved resume to PostgresSQL.";
    }

}
