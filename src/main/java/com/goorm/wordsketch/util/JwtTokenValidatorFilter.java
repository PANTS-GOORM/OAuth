package com.goorm.wordsketch.util;

import com.goorm.wordsketch.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;


import java.io.IOException;

@Component
@Qualifier("jwtTokenValidatorFilter")
@RequiredArgsConstructor
public class JwtTokenValidatorFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    /*
     * 'request'에서 token을 추출 및 검증
     * */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        jwtService.validateToken(request, response);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("authentication = " + authentication);
        filterChain.doFilter(request, response);
    }

    /*
     * '/oauth2/login/**' 요청에 대해서는 검증을 하지 않음
     * */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {


        String path = request.getServletPath();
        return path.startsWith("/login/oauth2") || path.startsWith("/oauth2") || "/".equals(path) || "/favicon.ico".equals(path) || "/Public/home/js/check.js".equals(path);
    }
}
