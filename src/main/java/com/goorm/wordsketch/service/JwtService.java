package com.goorm.wordsketch.service;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public interface JwtService {
    public void createAccessToken(HttpServletResponse response, Authentication authentication);

    public void createRefreshToken(HttpServletResponse response, Authentication authentication);

    public void reIssueToken(HttpServletResponse response, String refreshToken);

    public void validateToken(HttpServletRequest request, HttpServletResponse response);

    public void validateAccessToken(HttpServletRequest request, HttpServletResponse response);

    public void validateRefreshToken(HttpServletRequest request, HttpServletResponse response);

    public void updateRefreshToken(String refreshToken, String name);

    public String populateAuthorities(Collection<? extends GrantedAuthority> collection);

    public Cookie createCookie(String key, String value);
}
