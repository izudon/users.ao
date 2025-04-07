package com.incrage.ao.users;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
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

        // 特定の action に関してはJWT認証をスキップ
	if (path.startsWith( "/signup/" ) ||
	    path.startsWith( "/enter/"  ) ||
	    path.startsWith( "/login/"  )) {
            filterChain.doFilter(request, response);
            return;
        }

	// 以外は common の JWT認証
        super.doFilterInternal(request, response, filterChain);

	// action が plus の場合には認証情報をセッションに移動
	if (path.startsWith( "/plus/  " )) {
	    SecurityContext context = SecurityContextHolder.getContext();
	    request.getSession()
		.setAttribute("SAVED_AUTH", context.getAuthentication());
	    SecurityContextHolder.clearContext(); // SecurityContext はクリア
	}
    }
}
