package com.incrage.ao.users;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import com.incrage.ao.common.JwtAuthenticationFilter;
import com.incrage.ao.common.JwtTokenProvider;

import java.io.IOException;

@Component
public class UsersJwtAuthenticationFilter extends JwtAuthenticationFilter {

    public UsersJwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider) {
        super(jwtTokenProvider);
    }

    @Override
    protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain
    ) throws ServletException, IOException {

        String path = request.getRequestURI();

        // 特定のものに関してはJWT認証をスキップ
        if (path.startsWith("/enter/") || path.startsWith("/login/")) {
            filterChain.doFilter(request, response);
            return;
        }

	// 以外は common の JWT認証
        super.doFilterInternal(request, response, filterChain);
    }
}
