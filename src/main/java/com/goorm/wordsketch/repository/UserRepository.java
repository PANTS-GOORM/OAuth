package com.goorm.wordsketch.repository;

import com.goorm.wordsketch.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

    Optional<User> findByRefreshToken(String refreshToken);
}
