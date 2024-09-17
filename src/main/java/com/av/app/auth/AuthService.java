package com.av.app.auth;

import com.av.app.user.entity.User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

@Service
public class AuthService {
    public User validateUserByJwt(Jwt jwt) {
        return null;
    }
}
