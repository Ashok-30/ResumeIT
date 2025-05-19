package com.resumeit.resumeit_backend.repository;

import com.resumeit.resumeit_backend.model.Resume;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ResumeRepository extends JpaRepository<Resume, Long> {
}
