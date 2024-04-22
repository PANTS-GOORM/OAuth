package com.goorm.wordsketch.util;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.goorm.wordsketch.entity.User;
import com.goorm.wordsketch.repository.UserRepository;
import com.goorm.wordsketch.service.JwtService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtService jwtService;

    private final UserRepository userRepository;

    private final ObjectMapper objectMapper;

    @Value("${spring.security.oauth2.redirect-uri}")
    private String redirectUrl;

    // Todo: 배포하면 url 변경 필요
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        if (null != authentication) {
            jwtService.createAccessToken(response, authentication);
            jwtService.createRefreshToken(response, authentication);

            Optional<User> optionalUser = userRepository.findByEmail(authentication.getName());

            if (optionalUser.isPresent()) {
                User user = optionalUser.get();
                String userJson = objectMapper.writeValueAsString(user);
                String encodedUserJson = URLEncoder.encode(userJson, StandardCharsets.UTF_8);
                response.sendRedirect(redirectUrl + "?user=" + encodedUserJson);
            } else {
                String errorMessage = URLEncoder.encode("User not found", StandardCharsets.UTF_8);
                response.sendRedirect(redirectUrl + "?error=" + errorMessage);
            }
        }

    }
}
