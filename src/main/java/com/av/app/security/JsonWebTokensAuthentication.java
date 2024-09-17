package com.av.app.security;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

public class JsonWebTokensAuthentication extends JwtAuthenticationToken {

    private final UserDetails userDetails;
    public JsonWebTokensAuthentication(Jwt jwt, UserDetails principal) {
        super(jwt, principal.getAuthorities());
        this.userDetails = principal;
    }

    public UserDetails getUserDetails() {
        return userDetails;
    }
}
