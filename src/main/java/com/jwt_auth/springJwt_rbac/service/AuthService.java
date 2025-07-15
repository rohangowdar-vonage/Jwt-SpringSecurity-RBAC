package com.jwt_auth.springJwt_rbac.service;

import com.jwt_auth.springJwt_rbac.dto.AuthRequest;
import com.jwt_auth.springJwt_rbac.dto.AuthResponse;
import com.jwt_auth.springJwt_rbac.dto.UserInfoResponse;
import com.jwt_auth.springJwt_rbac.entities.Role;
import com.jwt_auth.springJwt_rbac.custom_enum.RoleName;
import com.jwt_auth.springJwt_rbac.entities.User;
import com.jwt_auth.springJwt_rbac.repository.RoleRepository;
import com.jwt_auth.springJwt_rbac.repository.UserRepository;
import com.jwt_auth.springJwt_rbac.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

import java.security.Principal;
import java.util.*;


@Service
@RequiredArgsConstructor
public class AuthService
{

    private final UserRepository userRepo;
    private final RoleRepository roleRepo;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;


    public ResponseEntity<String> userRegister(@RequestBody AuthRequest requestBody)
    {
        String username = requestBody.getUsername();
        String password = requestBody.getPassword();
        String department = requestBody.getDepartment();
        Long managerIdStr = requestBody.getManagerId();

        System.out.println(" Received registration for: " + username);
        System.out.println(" Department: " + department);
        System.out.println(" Manager ID received: " + managerIdStr);


        if (userRepo.existsByUsername(username)) {
            throw new RuntimeException("Username already exists");
        }

        Role roleUser = roleRepo.findByName(RoleName.ROLE_USER)
                .orElseThrow(() -> new RuntimeException("ROLE_USER not found"));

        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        user.setDepartment(department);
        user.setRole(roleUser);

        if (managerIdStr != null)
        {
            try {
                User manager = userRepo.findById(managerIdStr)
                        .orElseThrow(() -> new RuntimeException("Manager not found with id: " + managerIdStr));

                System.out.println(" Manager found: " + manager.getUsername() + " (ID: " + manager.getId() + ")");

                user.setManager(manager);
            } catch (NumberFormatException ex)
            {
                throw new RuntimeException("Invalid managerId format: must be a number");
            }
        }
        userRepo.save(user);

        return ResponseEntity.ok("User registered with ROLE_USER");
    }

    //This particular method will authenticate the user while login by checking all the essentials
    public ResponseEntity<?> authenticateUser(AuthRequest request) {
        try {
            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getUsername(),
                            request.getPassword()
                    )
            );
            UserDetails userDetails = (UserDetails) auth.getPrincipal();
            String token = jwtTokenProvider.generateToken(userDetails);

            return ResponseEntity.ok(new AuthResponse(token));
        } catch (IllegalArgumentException ex) {
            return ResponseEntity
                    .status(400)
                    .body(Map.of("error", "Invalid input: " + ex.getMessage()));

        } catch (BadCredentialsException ex) {
            return ResponseEntity
                    .status(401)
                    .body(Map.of("error", "Invalid username or password"));
        }catch (Exception ex) {
            return ResponseEntity
                    .status(500)
                    .body(Map.of("error", "Internal server error"));
        }
    }


    public ResponseEntity<String> promoteUser(Long userId, RoleName roleName)
    {
        promoteToRole(userId, roleName);
        return ResponseEntity.ok("User promoted to " + roleName.name());
    }

    public void promoteToRole(Long userId, RoleName roleName) {
        // Find the user
        User user = userRepo.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + userId));

        // Find the target role
        Role newRole = roleRepo.findByName(roleName)
                .orElseThrow(() -> new RuntimeException("Role not found: " + roleName));

        // Update the user's role
        user.setRole(newRole);

        // Save the user
        userRepo.save(user);
    }

    public ResponseEntity<UserInfoResponse> getLoggedInUserDetails(Principal principal)
    {
        String username = principal.getName();

        User user = userRepo.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found: " + username));

        String roleName = user.getRole().getName().name().replace("ROLE_", "");

        UserInfoResponse response = new UserInfoResponse(
                user.getUsername(),
                roleName,
                user.getDepartment()
        );

        return ResponseEntity.ok(response);
    }

    public List<User> getAllUsers()
    {
        return userRepo.findAll();
    }
}
