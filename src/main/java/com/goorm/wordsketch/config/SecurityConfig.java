package com.goorm.wordsketch.config;

import com.goorm.wordsketch.service.CustomOAuth2UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.util.Arrays;
import java.util.Collections;


@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CustomOAuth2UserService customOAuth2UserService;

    private final AuthenticationSuccessHandler authenticationSuccessHandler;

    private final OncePerRequestFilter oncePerRequestFilter;
    private final String loginPage;

    @Autowired
    public SecurityConfig(CustomOAuth2UserService customOAuth2UserService
            , AuthenticationSuccessHandler authenticationSuccessHandler
            , @Qualifier("jwtTokenValidatorFilter") OncePerRequestFilter oncePerRequestFilter
            , @Value("${spring.security.oauth2.login-page}") String loginPage) {
        this.customOAuth2UserService = customOAuth2UserService;
        this.authenticationSuccessHandler = authenticationSuccessHandler;
        this.oncePerRequestFilter = oncePerRequestFilter;
        this.loginPage = loginPage;
    }

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {
                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                        CorsConfiguration config = new CorsConfiguration();
                        config.setAllowedOrigins(Arrays.asList("http://localhost:3000", "https://www.wordsketch.site"));
                        config.setAllowedMethods(Collections.singletonList("*"));
                        config.setAllowCredentials(true);
                        config.setAllowedHeaders(Collections.singletonList("*"));
                        config.setMaxAge(3600L);
                        return config;
                    }
                }))
                .csrf(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(oncePerRequestFilter, BasicAuthenticationFilter.class)

                .authorizeHttpRequests((requests) -> requests
                        .requestMatchers("/", "login/oauth2/**", "/oauth2/**", "favicon.ico").permitAll()
                        .requestMatchers("/user").hasRole("User")
                        .anyRequest().authenticated())

                .oauth2Login(oauth2 -> oauth2
                        .loginPage(loginPage)
                        .userInfoEndpoint(userInfo -> userInfo.userService(customOAuth2UserService))
                        .successHandler(authenticationSuccessHandler)
                );
        return http.build();
    }

}
