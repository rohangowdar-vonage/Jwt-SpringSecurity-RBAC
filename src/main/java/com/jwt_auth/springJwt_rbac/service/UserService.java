package com.jwt_auth.springJwt_rbac.service;

import com.jwt_auth.springJwt_rbac.entities.User;
import com.jwt_auth.springJwt_rbac.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserService
{
    private final UserRepository userRepo;

    // view only their own details
    public User getOwnDetails(String username) {
        return userRepo.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found: " + username));
    }

    //get list of users they manage
    public List<User> getEmployeesUnderManager(String username) {
        return userRepo.findByManagerUsername(username);
    }
}
