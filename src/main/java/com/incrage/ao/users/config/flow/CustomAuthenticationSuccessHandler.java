package com.incrage.ao.users.config.flow;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseCookie;
import org.springframework.security
    .core.Authentication;
import org.springframework.security
    .web.authentication.AuthenticationSuccessHandler;
import org.springframework.security
    .oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Component;
import com.incrage.ao.common.JwtCookie;
import com.incrage.ao.common.JwtProvider;
import com.incrage.ao.users.service.AuthenticationService;

import java.io.IOException;

@Component
public class CustomAuthenticationSuccessHandler
    implements AuthenticationSuccessHandler {

    private final String RETURN_TO = "https://www.incrage.com/";
    private final JwtCookie jwtCookie;
    private final JwtProvider jwtProvider;
    private final AuthenticationService authService;

    public CustomAuthenticationSuccessHandler(
	JwtCookie jwtCookie,
	JwtProvider jwtProvider,
	AuthenticationService authService
    ) {
        this.jwtCookie = jwtCookie;
        this.jwtProvider = jwtProvider;
        this.authService = authService;
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException, ServletException {

	// 1. subject, registrationId の取得
	String subject = authentication.getName();
	String registrationId;
	if (authentication instanceof OAuth2AuthenticationToken oauthToken)
	    registrationId = oauthToken.getAuthorizedClientRegistrationId();
	else
	    throw new IllegalStateException();

	// 2. DBと引き当て
	com.incrage.ao.users.entity.Authentication dbauth
	    = authService.findOrSave(registrationId, subject);
	
	// 3. JWT の作成 -> Cookie にセット
        String token = jwtProvider.setClaims(dbauth.getId().toString());
	jwtCookie.set(token, response);

	// 4. 遷移先の復元・セッションの削除
	HttpSession session = request.getSession();
	String returnTo = (String) session.getAttribute("return_to");
	session.invalidate();

        // 5. リダイレクトをレスポンス
	response.sendRedirect(returnTo != null ? returnTo : RETURN_TO);
    }
}
