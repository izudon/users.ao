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
        String[] parts = uri.split("/",5);
        if (parts.length == 5){
	    if(Set.of("enter", "plus").contains(parts[1])){
		String registrationId = parts[2];
		String app            = parts[3];
		String rest           = parts[4];
		String query          = request.getQueryString();
		String targetRedirect
		    = "https://" + app + ".ao.incrage.com/" + rest
		    + (query != null ? "?" + query : "");

		request.getSession()
		    .setAttribute("target_url", targetRedirect);


		OAuth2AuthorizationRequest req
		    = defaultResolver.resolve(request, registrationId);
		if (req == null) return null;

		String redirectUri = "https://api-test.ao.incrage.com"
		    + "/users/login/oauth2/code/" + registrationId;

		return OAuth2AuthorizationRequest.from(req)
		    .redirectUri(redirectUri)
		    .build();
	    }
        }

        return null;
    }
}
