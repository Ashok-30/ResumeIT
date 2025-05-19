package com.resumeit.resumeit_backend.controller;

import com.resumeit.resumeit_backend.model.User;
import com.resumeit.resumeit_backend.repository.UserRepository;
import com.resumeit.resumeit_backend.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    @Autowired
    public AuthController(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/signup")
    public ResponseEntity<Map<String, String>> signup(@RequestBody Map<String, String> request) {
        String emailId = request.get("emailId");
        String password = request.get("password");
        String userType = request.get("userType");

        if (emailId == null || emailId.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Email ID is required"));
        }
        if (password == null || password.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Password is required"));
        }
        if (userType == null || userType.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "User type is required"));
        }

        emailId = emailId.toLowerCase();
        System.out.println("SignUp request: emailId=" + emailId + ", userType=" + userType);

        if (userRepository.findByEmailId(emailId).isPresent()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Email already exists"));
        }

        try {
            User.UserType type = User.UserType.valueOf(userType);
            User user = User.builder()
                    .emailId(emailId)
                    .password(passwordEncoder.encode(password))
                    .userType(type)
                    .build();
            userRepository.save(user);

            String token = jwtUtil.generateToken(emailId, userType);
            Map<String, String> response = new HashMap<>();
            response.put("token", token);
            response.put("userType", userType);
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid user type"));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody Map<String, String> request) {
        String emailId = request.get("emailId");
        String password = request.get("password");

        if (emailId == null || emailId.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Email ID is required"));
        }
        if (password == null || password.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Password is required"));
        }

        emailId = emailId.toLowerCase();
        Optional<User> userOpt = userRepository.findByEmailId(emailId);
        if (userOpt.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "User not found"));
        }

        User user = userOpt.get();
        if (!passwordEncoder.matches(password, user.getPassword())) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid password"));
        }

        String token = jwtUtil.generateToken(emailId, user.getUserType().name());
        Map<String, String> response = new HashMap<>();
        response.put("token", token);
        response.put("userType", user.getUserType().name());
        return ResponseEntity.ok(response);
    }

    @PutMapping("/update-user-type")
    public ResponseEntity<Map<String, String>> updateUserType(@RequestBody Map<String, String> request) {
        String userType = request.get("userType");
        String emailId = SecurityContextHolder.getContext().getAuthentication().getName();

        if (userType == null || userType.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "User type is required"));
        }
        if (emailId == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        emailId = emailId.toLowerCase();
        System.out.println("UpdateUserType request: emailId=" + emailId + ", userType=" + userType);

        Optional<User> userOpt = userRepository.findByEmailId(emailId);
        if (userOpt.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "User not found"));
        }

        try {
            User.UserType type = User.UserType.valueOf(userType);
            User user = userOpt.get();
            user.setUserType(type);
            userRepository.save(user);

            String token = jwtUtil.generateToken(emailId, userType);
            Map<String, String> response = new HashMap<>();
            response.put("token", token);
            response.put("userType", userType);
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid user type"));
        }
    }
}