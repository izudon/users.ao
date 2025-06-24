package com.incrage.ao.users;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import com.incrage.ao.common.JwtCookie;
import com.incrage.ao.common.JwtProvider;

import java.io.IOException;

@Component
public class CustomAuthenticationSuccessHandler
    implements AuthenticationSuccessHandler {

    private final JwtCookie jwtCookie;
    private final JwtProvider jwtProvider;

    public CustomAuthenticationSuccessHandler(
	JwtCookie jwtCookie,
	JwtProvider jwtProvider
    ) {
        this.jwtCookie = jwtCookie;
        this.jwtProvider = jwtProvider;
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException, ServletException {

	// 1. JWT の作成
        String token = jwtProvider.setClaims(authentication.getName());

	// 2. JWT -> Cookie
	jwtCookie.setToken(token, response);

	// 3. リダイレクトをレスポンス
        String targetUrl
	    = (String) request.getSession().getAttribute("redirect");
        response.sendRedirect(targetUrl != null ? targetUrl : "/");
    }
}
