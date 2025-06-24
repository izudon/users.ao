package com.incrage.ao.common;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security
    .authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security
    .authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;

import java.io.IOException;
import java.util.Collections;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtCookie jwtCookie;
    private final JwtProvider jwtProvider;

    public JwtAuthenticationFilter(
        JwtCookie jwtCookie,
        JwtProvider jwtProvider
    ) {
        this.jwtCookie = jwtCookie;
        this.jwtProvider = jwtProvider;
    }

    @Override
    protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain
    ) throws ServletException, IOException {
        try {
	    // 1. Cookie から JWT を取得
	    String token = jwtCookie.getToken(request);
	    if (token == null)
		throw new RuntimeException("JWT Cookie is not set");

	    // 2. JWT を 検証
	    Claims claims = jwtProvider.getClaims(token);

	    // 3. sub を JWT から取得
            String subject = claims.getSubject();
	    if (subject == null)
		throw new RuntimeException("sub is not set in JWT");
	    
	    // 4. DBと引き当て・相互作用（なければ作る）
	    // ToDo
	    
            // 5. SecurityContext に設定
            Authentication authentication
		= new UsernamePasswordAuthenticationToken(
                subject, null, Collections.emptyList()
            );
            SecurityContextHolder.getContext()
		.setAuthentication(authentication);

        } catch (Exception e) {
            // 401 を返してしまう。
            SecurityContextHolder.clearContext();
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
		"Unauthorized: " + e.getMessage());
            return;
	}
        filterChain.doFilter(request, response); // -> 最終的に 401 になるはず
    }
}
