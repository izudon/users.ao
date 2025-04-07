package com.incrage.ao.users;

import java.util.Set;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.client
    .registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client
    .web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client
    .web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core
    .endpoint.OAuth2AuthorizationRequest;

public class CustomAuthorizationRequestResolver
    implements OAuth2AuthorizationRequestResolver {

    private final OAuth2AuthorizationRequestResolver defaultResolver;

    public CustomAuthorizationRequestResolver
	(ClientRegistrationRepository repo) {
        this.defaultResolver
	    = new DefaultOAuth2AuthorizationRequestResolver(repo, "/dummy");
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        return this.resolve(request, request.getRequestURI());
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request,
					      String uri) {
        String[] parts = uri.split("/");
	String action         = null ;
	String registrationId = null ;
	String ticketCode     = null ;
	boolean doRequest     = false; // OAuth2 やるというフラグ

        if (parts.length > 1) action         = parts[1];
        if (parts.length > 2) registrationId = parts[2];
        if (parts.length > 3) ticketCode     = parts[3];

	if( "signup".equals(action)
	    && ticketCode != null ){
	    saveAction(request, action);
	    saveTicketCode(request, ticketCode);
	    saveRedirect(request);
	    doRequest         = true; // フラグ ON
	}
	if ( Set.of("enter", "plus").contains(action)
	     && registrationId != null ){
	    saveAction(request, action);
	    saveRedirect(request);
	    doRequest         = true; // フラグ ON
	}
	if ( doRequest ){
	    return buildOAuth2Request(request, registrationId); // OAuth2 やる
	}
	
        return null;
    }

    private void saveAction
	(HttpServletRequest request, String action) {
	request.getSession()
	    .setAttribute("action", action );
    }
    private void saveTicketCode
	(HttpServletRequest request, String ticketCode) {
	request.getSession()
	    .setAttribute("redirect", ticketCode );
    }
    private void saveRedirect
	(HttpServletRequest request) {
	request.getSession()
	    .setAttribute("redirect", request.getParameter("redirect"));
    }
    private OAuth2AuthorizationRequest buildOAuth2Request
	(HttpServletRequest request, String registrationId) {

	// OAuth2 リクエストオブジェクト
	OAuth2AuthorizationRequest req
	    = defaultResolver.resolve(request, registrationId);
	if (req == null) return null;
	    
	// カスタマイズのリダイレクトバックポイント
	String redirectUri
	    = oauth2RedirectUri(request, registrationId);
	
	// 再ビルドして返す（セッションにも保存）
	return OAuth2AuthorizationRequest.from(req)
	    .redirectUri(redirectUri)
	    .build();
    }
    private String oauth2RedirectUri(HttpServletRequest request,
				    String registrationId) {
	String host = request.getHeader("X-Forwarded-Host");
	if (host == null || host.isEmpty()) {
	    host = request.getHeader("Host");
	}
	return "https://" + host + "/users/login/oauth2/code/"
	    + registrationId;
    }
}
