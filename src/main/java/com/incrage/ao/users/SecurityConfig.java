package com.incrage.ao.users;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security
    .config.annotation.web.builders.HttpSecurity;
import org.springframework.security
    .web.SecurityFilterChain;
import org.springframework.security
    .oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security
    .web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security
    .config.http.SessionCreationPolicy;
import org.springframework.security
    .config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security
    .config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security
    .config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.core.annotation.Order;
import com.incrage.ao.common.JwtAuthenticationFilter;

@Configuration
public class SecurityConfig {

    private final ClientRegistrationRepository repo;
    private final CustomAuthenticationSuccessHandler onSuccess;
    private final CustomAuthenticationFailureHandler onFailure;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public SecurityConfig(
        ClientRegistrationRepository repo,
        CustomAuthenticationSuccessHandler onSuccess,
        CustomAuthenticationFailureHandler onFailure,
        JwtAuthenticationFilter jwtAuthenticationFilter
    ) {
        this.repo = repo;
        this.onSuccess = onSuccess;
        this.onFailure = onFailure;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean
    @Order(1)
    public SecurityFilterChain oauth2FilterChain(HttpSecurity http)
	throws Exception {
	http = myBasicHttpSecurity(http);
        http
            .securityMatcher("/enter/**", "/login/**")
            .authorizeHttpRequests(auth -> auth
                .anyRequest().permitAll()
            )
            .oauth2Login(oauth -> oauth
                .authorizationEndpoint(endpoint -> endpoint
                    .authorizationRequestResolver(
                        new CustomAuthorizationRequestResolver(repo)
                    )
                )
                .successHandler(onSuccess)
		.failureHandler(onFailure)
	    );
	
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain apiFilterChain(HttpSecurity http)
	throws Exception {
	http = myBasicHttpSecurity(http);
        http
	    .sessionManagement(session -> session
		.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated())
            .addFilterBefore(jwtAuthenticationFilter,
	        UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    //----------
    
    private HttpSecurity myBasicHttpSecurity(HttpSecurity http)
	throws Exception {
	return http
            .cors(cors -> cors.disable()) // CORS 無効
            .csrf(csrf -> csrf.disable()) // CSRF 無効
            .with(new LogoutConfigurer<HttpSecurity>(), 
                  config -> config.disable()) // ログアウト無効
	    // 未認証を匿名ユーザでラップしない
	    .anonymous((anonymous) -> anonymous.disable())
            // リクエストキャッシュ機能 無効
            .requestCache(requestCache -> requestCache.disable())
            // サーブレットAPI連携（isUserInRole() 等） 無効
            .servletApi(servletApi -> servletApi.disable());
    }
}
