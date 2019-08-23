package com.example.security.jwtsecurity.security;

import com.example.security.jwtsecurity.model.JwtUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JwtValidator {

    @Value("${jwt.secret}")
    private String secret;

    public JwtUser validate(String token) {

        JwtUser jwtUser = null;

        try {
            Claims body = Jwts.parser()
                    .setSigningKey(this.secret)
                    .parseClaimsJws(token)
                    .getBody();

            jwtUser = new JwtUser();

            jwtUser.setUserName(body.getSubject());
            jwtUser.setId(Long.parseLong((String) body.get("userId")));
            jwtUser.setRole((String) body.get("role"));

        } catch (Exception e) {
            System.out.println(e);
        }

        return jwtUser;
    }
}