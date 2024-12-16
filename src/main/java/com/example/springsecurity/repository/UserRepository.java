package com.example.springsecurity.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import com.example.springsecurity.entity.UserEntity;

public interface UserRepository extends JpaRepository<UserEntity, Integer> {
    boolean existsByUsername(String username);

    UserEntity findByUsername(String username);
}
