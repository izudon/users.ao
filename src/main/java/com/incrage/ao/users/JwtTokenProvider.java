package com.incrage.ao.users;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Date;

import io.jsonwebtoken.security.Keys;
import java.security.Key;

@Component
public class JwtTokenProvider {

    private final Key secretKey;
    private final long expirationMs;

    public JwtTokenProvider(
        @Value("${jwt.secret-key}") String secret,
        @Value("${jwt.expiration-ms}") long expirationMs
    ) {
        this.secretKey
	    = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.expirationMs = expirationMs;
    }

    public String createToken(Authentication authentication) {
        String subject = authentication.getName();
        Date now = new Date();
        Date expiry = new Date(now.getTime() + expirationMs);

        return Jwts.builder()
                .setSubject(subject)
                .setIssuedAt(now)
                .setExpiration(expiry)
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }
}
