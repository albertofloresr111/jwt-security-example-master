package com.example.security.jwtsecurity.security;

import com.example.security.jwtsecurity.model.JwtUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JwtGenerator {

    @Value("${jwt.secret}")
    private String secret;

    private final static String USER_ID = "userId";
    private final static String ROLE = "role";

    public String generate(JwtUser jwtUser) {
        Claims claims = Jwts.claims()
                .setSubject(jwtUser.getUserName());

        claims.put(USER_ID, String.valueOf(jwtUser.getId()));
        claims.put(ROLE, jwtUser.getRole());

        return Jwts.builder()
                .setClaims(claims)
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();
    }

}