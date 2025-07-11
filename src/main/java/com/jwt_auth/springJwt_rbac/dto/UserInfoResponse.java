package com.jwt_auth.springJwt_rbac.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class UserInfoResponse
{
    private String username;
    private String role;
    private String department;
}


