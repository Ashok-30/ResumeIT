package com.resumeit.resumeit_backend.service;

import com.resumeit.resumeit_backend.model.User;
import com.resumeit.resumeit_backend.repository.UserRepository;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.stereotype.Service;

@Service
public class CustomOidcUserService extends OidcUserService {

    private final UserRepository userRepository;

    public CustomOidcUserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) {
        OidcUser oidcUser = super.loadUser(userRequest);
        String email = oidcUser.getEmail();

        if (email == null) {
            throw new IllegalStateException("Email not found in OIDC response");
        }

        userRepository.findByEmailId(email).orElseGet(() -> {
            User user = User.builder()
                    .emailId(email)
                    .password("")
                    .userType(User.UserType.JOB_SEEKER)
                    .build();
            return userRepository.saveAndFlush(user);
        });

        return oidcUser; // let Spring Security handle rest
    }
}
