package com.goorm.wordsketch.util;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.Cookie;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

@Component
public class CustomLogoutHandler implements LogoutHandler {

    private List<Function<HttpServletRequest, Cookie>> cookiesToClear;

    public CustomLogoutHandler(@Value("${jwt.access.cookie}") String accessCookie,
                               @Value("${jwt.refresh.cookie}") String refreshCookie,
                               @Value("${jwt.admin.cookie}") String adminCookie) {
        cookiesToClear = new ArrayList<>();
        addCookieFunction(accessCookie);
        addCookieFunction(refreshCookie);
        addCookieFunction(adminCookie);
    }

    /*
    * 지워야 할 쿠키를 cookiesToClear에 추가함
    * */
    private void addCookieFunction(String cookieName) {
        cookiesToClear.add(request -> {
            Cookie cookie = new Cookie(cookieName, null);
            cookie.setPath(request.getContextPath().isEmpty() ? "/" : request.getContextPath());
            cookie.setDomain("wordsketch.site");
            cookie.setMaxAge(0);
            cookie.setSecure(request.isSecure());
            return cookie;
        });
    }

    /*
    * cookiesToClear를 순회하며, 각 함수를 현재 요청에 적용하여 결과인 쿠키를 응답에 추가
    * */
    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        cookiesToClear.forEach(cookieFunction -> {
            Cookie cookie = cookieFunction.apply(request);
            response.addCookie(cookie);
        });
    }
}
