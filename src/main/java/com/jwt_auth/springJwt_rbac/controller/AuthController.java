package com.jwt_auth.springJwt_rbac.controller;


import com.jwt_auth.springJwt_rbac.dto.AuthRequest;
import com.jwt_auth.springJwt_rbac.dto.UserInfoResponse;
import com.jwt_auth.springJwt_rbac.entities.RoleName;
import com.jwt_auth.springJwt_rbac.entities.User;
import com.jwt_auth.springJwt_rbac.security.JwtTokenProvider;
import com.jwt_auth.springJwt_rbac.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.web.bind.annotation.*;
import java.security.Principal;
import java.util.List;
import java.util.Map;


@RestController
@RequestMapping
@RequiredArgsConstructor
public class AuthController
{
    private final AuthService authService;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;


    @PostMapping("/register")
    public ResponseEntity<String> userRegister(@RequestBody Map<String,String> requestBody)
    {
        return authService.userRegister(requestBody);
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@RequestBody AuthRequest request)
    {
        return authService.authenticateUser(request);
    }

    @PutMapping("/promote/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> promoteExistingUser(@PathVariable Long userId,@RequestBody Map<String, String> request) {
        RoleName role = RoleName.valueOf( request.get("role"));
        authService.promoteUser(userId,role);
        return ResponseEntity.ok("User promoted to " + role.name());
   }

    @GetMapping("/me")
    @PreAuthorize("hasAnyRole('USER',MANAGER)")
    public ResponseEntity<UserInfoResponse> getLoggedInUserDetails(Principal principal)
    {
        return authService.getLoggedInUserDetails(principal);
    }

    @GetMapping("/allUsers")
    @PreAuthorize("hasRole('MANAGER')")
    public ResponseEntity<List<User>> getAllUsers()
    {
        return ResponseEntity.ok(authService.getAllUsers());
    }
}
