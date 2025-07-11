package com.jwt_auth.springJwt_rbac.repository;

import com.jwt_auth.springJwt_rbac.entities.Role;
import com.jwt_auth.springJwt_rbac.entities.RoleName;
import com.jwt_auth.springJwt_rbac.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.*;

public interface RoleRepository extends JpaRepository<Role,Long>
{
    Optional<Role> findByName(RoleName roleName);

}
