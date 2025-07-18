package com.jwt_auth.springJwt_rbac.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class AuthRequest
{
    private String username;
    private String password;
    private String department;
    //private Long roleId;
    private Long managerId;
}
