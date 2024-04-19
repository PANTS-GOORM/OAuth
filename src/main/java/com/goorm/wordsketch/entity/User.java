package com.goorm.wordsketch.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.sql.Timestamp;

@Builder
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "\"user\"")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    @Column(name = "social_id", nullable = false, columnDefinition = "VARCHAR(300)")
    private String email;

    @Column(name = "social_type", nullable = false)
    private UserSocialType socialType;

    @Column(name = "nickname", nullable = false, columnDefinition = "VARCHAR(300)")
    private String nickname;

    @Column(name = "profile_img_url", nullable = false, columnDefinition = "VARCHAR(300)")
    private String profileImg;

    @Column(name = "refresh_token", nullable = false, columnDefinition = "VARCHAR(300)")
    private String refreshToken;

    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false)
    private UserRole role;

    @Column(name = "isAdmin", nullable = false, columnDefinition = "BOOLEAN")
    private boolean isAdmin;

    // Timestamp의 값을 현재 시간으로 자동 설정
    @Column(name = "created_date", nullable = false, updatable = false, insertable = false, columnDefinition = "TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
    private Timestamp createdDate;

    @Column(name = "last_modified_date", nullable = false, insertable = false, columnDefinition = "TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
    private Timestamp lastModifiedDate;

    public String updateRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
        return refreshToken;
    }
}
