package com.goorm.wordsketch.service;

import com.goorm.wordsketch.entity.User;
import com.goorm.wordsketch.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Service
@RequiredArgsConstructor
@Getter
public class JwtServiceImpl implements JwtService {

    @Value("${jwt.secretKey}")
    private String secretKey;

    @Value("${jwt.access.expiration}")
    private Long accessTokenExpirationPeriod;

    @Value("${jwt.refresh.expiration}")
    private Long refreshTokenExpirationPeriod;

    @Value("${jwt.access.cookie}")
    private String accessCookie;

    @Value("${jwt.refresh.cookie}")
    private String refreshCookie;

    /**
     * OAuth2 로그인이기 때문에 username은 사실상 email
     */
    private final String ISSUER = "WORD SKETCH";
    private final String ACCESS_TOKEN_SUBJECT = "AccessToken";
    private final String REFRESH_TOKEN_SUBJECT = "RefreshToken";
    private final String USERNAME_CLAIM = "username";
    private final String AUTHRITIES_CLAIM = "authorities";
    private final String BEARER = "Bearer ";

    private final UserRepository userRepository;

    /**
     * AccessToken 생성, 응답 헤더에 추가
     *
     * @param response       응답
     * @param authentication 인증, 인가 정보
     */
    public void createAccessToken(HttpServletResponse response, Authentication authentication) {
        SecretKey key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
        String jwt = Jwts.builder().issuer(ISSUER).subject(ACCESS_TOKEN_SUBJECT)
                .claim(USERNAME_CLAIM, authentication.getName())
                .claim(AUTHRITIES_CLAIM, populateAuthorities(authentication.getAuthorities()))
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + accessTokenExpirationPeriod))
                .signWith(key).compact();

        response.addCookie(createCookie(accessCookie, jwt));
    }

    /**
     * RefreshToken 생성, 응답 헤더에 추가 및 db에 저장
     *
     * @param response       응답
     * @param authentication 인증, 인가 정보
     */
    public void createRefreshToken(HttpServletResponse response, Authentication authentication) {
        SecretKey key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
        String jwt = Jwts.builder().issuer(ISSUER).subject(REFRESH_TOKEN_SUBJECT)
                .claim(USERNAME_CLAIM, authentication.getName())
                .claim(AUTHRITIES_CLAIM, populateAuthorities(authentication.getAuthorities()))
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + refreshTokenExpirationPeriod))
                .signWith(key).compact();

        response.addCookie(createCookie(refreshCookie, jwt));
        updateRefreshToken(jwt, authentication.getName());
    }

    /**
     * AccessToken, RefreshToken 재발급
     * AccessToken 기간이 유효하지 않고 RefreshToken 기간이 유효할 떄 사용
     *
     * @param response     사용자 응답. 'createAccessToken'과 'createRefreshToken'을 호출할 때 사용
     * @param refreshToken 유효한 리프레쉬 토큰. DB에서 user를 찾는데 사용
     */
    public void reIssueToken(HttpServletResponse response, String refreshToken) {
        Optional<User> user = userRepository.findByRefreshToken(refreshToken);
        if (user.isPresent()) {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            createAccessToken(response, authentication);
            createRefreshToken(response, authentication);
        }
    }

    /**
     * AccessToken 검증
     *
     * @param request  사용자 요청. 헤더에서 토큰을 추출하기 위해 사용
     * @param response 응답. 예외처리를 위해 사용
     */
    public void validateAccessToken(HttpServletRequest request, HttpServletResponse response) {
        String jwt = null;
        Cookie[] cookies = request.getCookies();

        try {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(refreshCookie)) {
                    jwt = cookie.getValue();
                }
            }
            if (jwt != null) {
                for (Cookie cookie : cookies) {
                    if (cookie.getName().equals(accessCookie)) {
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
                    } catch (ExpiredJwtException expiredJwtException) {
                        validateRefreshToken(request, response);
                    } catch (SignatureException signatureException) {
                        throw new SecurityException("토큰 서명 검증에 실패하였습니다");
                    } catch (Exception exception) {
                        throw new RuntimeException("예상하지 못한 오류가 발생했습니다.", exception);
                    }
                }
            }
        } catch (NullPointerException e) {
            throw new NullPointerException("엑세스토큰 검증 실패: 토큰이 확인되지 않습니다.");
        }
    }

    /**
     * RefreshToken 검증
     *
     * @param request  사용자 요청. 헤더에서 토큰을 추출하기 위해 사용
     * @param response 응답. 예외처리를 위해 사용
     */
    public void validateRefreshToken(HttpServletRequest request, HttpServletResponse response) {
        String jwt = null;
        Cookie[] cookies = request.getCookies();

        try {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(refreshCookie)) {
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

                    reIssueToken(response, jwt);
                } catch (ExpiredJwtException expiredJwtException) {
                    throw new CredentialsExpiredException("토큰 유효기간 검증에 실패했습니다");
                } catch (SignatureException signatureException) {
                    throw new SecurityException("토큰 서명 검증에 실패하였습니다");
                } catch (Exception exception) {
                    throw new RuntimeException("예상하지 못한 오류가 발생했습니다.", exception);
                }
            }
        } catch (NullPointerException e) {
            throw new NullPointerException("리프레쉬토큰 검증 실패: 토큰이 확인되지 않습니다.");
        }
    }

    /**
     * RefreshToken DB 저장(업데이트)
     *
     * @param refreshToken 리프레쉬 토큰. DB에 업데이트할 값
     * @param name         OAuth2를 사용하기 때문에 사실 email이다. 이를 사용해 DB에서 user를 찾을 수 있음
     */
    public void updateRefreshToken(String refreshToken, String name) {
        Optional<User> optionalUser = userRepository.findByEmail(name);
        if (optionalUser.isPresent()) {
            User user = optionalUser.get();
            user.updateRefreshToken(refreshToken);
            userRepository.save(user);
        } else {
            new Exception("일치하는 회원이 없습니다.");
        }
    }

    /**
     * 권한들을 String으로 반환
     *
     * @param collection 권한들 ex.ADMIN, USER
     * @return authorities 중복이 없고, 쉼표로 구분된 문자열 권한들
     */
    public String populateAuthorities(Collection<? extends GrantedAuthority> collection) {
        Set<String> authoritiesSet = new HashSet<>();
        for (GrantedAuthority authority : collection) {
            authoritiesSet.add(authority.getAuthority());
        }
        return String.join(",", authoritiesSet);
    }

    /**
     * JWT를 쿠키로 반환
     *
     * @param key   쿠키의 키
     * @param value 쿠키의 값(AccessToken, RefreshToken이 들어롬)
     * @return Cookie 생성된 쿠키
     * Todo: 배포하면 serSecure(true); 주석 해제
     */
    public Cookie createCookie(String key, String value) {
        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(Math.toIntExact(refreshTokenExpirationPeriod));
        // cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setHttpOnly(true);

        return cookie;
    }
}