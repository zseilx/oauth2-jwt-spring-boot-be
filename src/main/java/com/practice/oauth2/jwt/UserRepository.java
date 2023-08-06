package com.practice.oauth2.jwt;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Long> {
	public Optional<UserEntity> findByUserId(String userId);
}

