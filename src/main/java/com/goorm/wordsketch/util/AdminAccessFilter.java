package com.goorm.wordsketch.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.goorm.wordsketch.entity.User;
import com.goorm.wordsketch.entity.UserRole;
import com.goorm.wordsketch.entity.UserSocialType;
import com.goorm.wordsketch.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

@Component
@Qualifier("adminVerifierFilter")
@RequiredArgsConstructor
public class AdminAccessFilter extends OncePerRequestFilter {

    @Value("${jwt.secretKey}")
    private String secretKey;

    @Value("${jwt.admin.cookie}")
    private String adminCookie;

    @Value("${spring.security.oauth2.redirect-uri}")
    private String redirectUrl;

    private final String USERNAME_CLAIM = "username";
    private final String AUTHRITIES_CLAIM = "authorities";

    private final UserRepository userRepository;
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // 요청 URL을 가져옵니다.
        String path = request.getRequestURI();

        // /oauth2/authorization 경로에 대한 요청만 처리합니다.
        if (path.startsWith("/oauth2/authorization")) {
            String jwt = null;
            Cookie[] cookies = request.getCookies();

            try {
                for (Cookie cookie : cookies) {
                    if (cookie.getName().equals(adminCookie)) {
                        jwt = cookie.getValue();
                    }
                }

                if (jwt != null) {
                    try {
                        SecretKey key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));

                        Claims claims = Jwts.parser()
                                .verifyWith(key)
                                .build()
                                .parseSignedClaims(jwt)
                                .getPayload();
                        String username = String.valueOf(claims.get(USERNAME_CLAIM));
                        String authorities = String.valueOf(claims.get(AUTHRITIES_CLAIM));
                        Authentication auth = new UsernamePasswordAuthenticationToken(username, null,
                                AuthorityUtils.commaSeparatedStringToAuthorityList(authorities));
                        SecurityContextHolder.getContext().setAuthentication(auth);

                        User user;
                        Optional<User> optionalUser = userRepository.findByEmail("ddongpants@groom.com");

                        if (optionalUser.isPresent()) {
                            user = optionalUser.get();
                        } else {
                            user = new User().builder()
                                    .email("ddongpants@groom.com")
                                    .socialType(UserSocialType.ADMIN)
                                    .nickname("ADMIN")
                                    .profileImg("https://lh3.googleusercontent.com/drive-viewer/AKGpihY7VAsaACl-0bWQJBjSCYtJt_LEQ2fcKu_0BOpdwHYtsXzQyxfhZ0B9jDltD8Sz5p1-oXz_tU5m7MbTm0apgTEHhY06NPUzuME=w1920-h953-rw-v1")
                                    .role(UserRole.ADMIN)
                                    .refreshToken(jwt)
                                    .isAdmin(true)
                                    .build();
                        }

                        userRepository.save(user);

                        String userJson = objectMapper.writeValueAsString(user);
                        String encodedUserJson = URLEncoder.encode(userJson, StandardCharsets.UTF_8);
                        response.sendRedirect(redirectUrl + "?user=" + encodedUserJson);

                    } catch (SignatureException signatureException) {
                        throw new SecurityException("토큰 서명 검증에 실패하였습니다");
                    } catch (Exception exception) {
                        throw new RuntimeException("예상하지 못한 오류가 발생했습니다.", exception);
                    }
                } else {
                    doFilter(request, response, filterChain);
                }
            } catch (NullPointerException e) {
                doFilter(request, response, filterChain);
            }

        } else {
            doFilter(request, response, filterChain);
        }

    }


}
