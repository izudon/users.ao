package com.incrage.ao.users;

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

import java.io.IOException;

@Component
public class CustomAuthenticationSuccessHandler
    implements AuthenticationSuccessHandler {

    private final String RETURN_TO = "https://www.incrage.com/";
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

	// 1. subject, registrationId の取得
	String subject = authentication.getName();
	String registrationId;
	if (authentication instanceof OAuth2AuthenticationToken oauthToken)
	    registrationId = oauthToken.getAuthorizedClientRegistrationId();

	// 2. DBと引き当て（findOrSave） // ToDo
	String jwtSubject = authentication.getName();
	// ToDo 本来はaccounts テーブルのキー ^^^
	
	// 3. JWT の作成 -> Cookie にセット
        String token = jwtProvider.setClaims(jwtSubject);
	jwtCookie.setToken(token, response);

	// 4. 遷移先の復元・セッションの削除
	HttpSession session = request.getSession();
	String returnTo = (String) session.getAttribute("return_to");
	session.invalidate();

        // 5. リダイレクトをレスポンス
	response.sendRedirect(returnTo != null ? returnTo : RETURN_TO);
    }
}
