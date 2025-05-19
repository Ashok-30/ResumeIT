package com.resumeit.resumeit_backend.config;

import com.resumeit.resumeit_backend.model.User;
import com.resumeit.resumeit_backend.repository.UserRepository;
import com.resumeit.resumeit_backend.service.CustomOAuth2UserService;
import com.resumeit.resumeit_backend.util.JwtUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Optional;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final CustomOAuth2UserService oauth2UserService;

    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter,
                          CustomOAuth2UserService oauth2UserService,
                          UserRepository userRepository,
                          JwtUtil jwtUtil) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.oauth2UserService = oauth2UserService;
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/signup", "/api/auth/login", "/login/oauth2/code/google").permitAll()
                        .requestMatchers("/api/auth/update-user-type").authenticated()
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(userInfo -> userInfo.userService(oauth2UserService))
                        .successHandler((request, response, authentication) -> {
                            OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
                            String email = oAuth2User.getAttribute("email");

                            if (email == null) {
                                response.setStatus(400);
                                response.getWriter().write("{\"error\":\"Email not found in OAuth2 response\"}");
                                return;
                            }

                            email = email.toLowerCase();
                            Optional<User> userOpt = userRepository.findByEmailId(email);
                            if (userOpt.isEmpty()) {
                                response.setStatus(500);
                                response.getWriter().write("{\"error\":\"User not found after OAuth2 login\"}");
                                return;
                            }

                            User user = userOpt.get();
                            String token = jwtUtil.generateToken(email, user.getUserType().name());

                            response.setContentType("application/json");
                            response.getWriter().write("{\"token\":\"" + token + "\",\"userType\":\"" + user.getUserType().name() + "\"}");
                        })
                        .failureHandler((request, response, exception) -> {
                            response.setStatus(401);
                            response.getWriter().write("{\"error\":\"OAuth2 login failed: " + exception.getMessage() + "\"}");
                        })
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
