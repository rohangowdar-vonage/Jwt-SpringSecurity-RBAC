package com.jwt_auth.springJwt_rbac.repository;

import com.jwt_auth.springJwt_rbac.entities.RoleName;
import com.jwt_auth.springJwt_rbac.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long>
{
    Optional<User> findByUsername(String username);
    List<User> findByManagerUsername(String managerUsername); // Employees under manager
    Optional<User> findByUsernameAndRole_Name(String username, RoleName role);

    boolean existsByUsername(String username);
}
