package com.resumeit.resumeit_backend.service;

import com.resumeit.resumeit_backend.model.User;
import com.resumeit.resumeit_backend.repository.UserRepository;
import com.resumeit.resumeit_backend.model.CustomOAuth2User;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.Map;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    public CustomOAuth2UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) {
        System.out.println("===> OAuth2: inside loadUser");

        OAuth2User oAuth2User = super.loadUser(userRequest);
        Map<String, Object> attributes = oAuth2User.getAttributes();
        String email = (String) attributes.get("email");

        if (email == null) {
            throw new IllegalArgumentException("Email not found in OAuth2 response.");
        }

        User user = userRepository.findByEmailId(email).orElseGet(() -> {
            System.out.println("===> Creating new user for email: " + email);
            User newUser = User.builder()
                    .emailId(email)
                    .password("")
                    .userType(User.UserType.JOB_SEEKER)
                    .build();
            return userRepository.saveAndFlush(newUser);
        });

        return new CustomOAuth2User(
                user,
                Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")),
                attributes,
                "email"
        );
    }
}
