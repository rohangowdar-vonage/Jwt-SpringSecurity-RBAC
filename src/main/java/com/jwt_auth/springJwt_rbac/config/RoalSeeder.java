package com.jwt_auth.springJwt_rbac.config;

import com.jwt_auth.springJwt_rbac.entities.Role;
import com.jwt_auth.springJwt_rbac.entities.RoleName;
import com.jwt_auth.springJwt_rbac.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
@RequiredArgsConstructor
public class RoalSeeder implements CommandLineRunner
{
    @Autowired
    private RoleRepository roleRepo;

    @Override
    public void run(String... args) {
        Arrays.stream(RoleName.values()).forEach(roleName -> {
            if (roleRepo.findByName(roleName).isEmpty()) {
                Role role = new Role();
                role.setName(roleName);
                role.setUsers(new ArrayList<>());
                roleRepo.save(role);
            }
        });
    }
}
