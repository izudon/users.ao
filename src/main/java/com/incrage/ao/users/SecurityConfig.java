package com.incrage.ao.users;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security
    .config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security
    .oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security
    .config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security
    .config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security
    .config.annotation.web.configurers.LogoutConfigurer;

@Configuration
public class SecurityConfig {

    private final ClientRegistrationRepository repo;
    private final CustomAuthenticationSuccessHandler handler;

    public SecurityConfig(
        ClientRegistrationRepository repo,
        CustomAuthenticationSuccessHandler handler
    ) {
        this.repo = repo;
        this.handler = handler;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http)
	throws Exception {
        http

	    // 不要な認証機能等を disable
	    .csrf(csrf -> csrf.disable())       // CSRF 無効
	    .with(new FormLoginConfigurer<HttpSecurity>()
		  , config -> config.disable()) // フォームログイン無効
	    .with(new HttpBasicConfigurer<HttpSecurity>()
		  , config -> config.disable()) // Basic認証無効
	    .with(new LogoutConfigurer<HttpSecurity>()
		  , config -> config.disable()) // ログアウト機能無効

            .authorizeHttpRequests(authz -> authz
                .anyRequest().permitAll()
            )
	    
	    // OAuth2 の設定
            .oauth2Login(oauth -> oauth
                .authorizationEndpoint(endpoint -> endpoint
                    .authorizationRequestResolver(
                        new CustomAuthorizationRequestResolver(repo)
                    )
                )
                .successHandler(handler)
            );
        return http.build();
    }
}
