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
import com.incrage.ao.common.JwtAuthenticationEntryPoint;
    
@Configuration
public class SecurityConfig {

    private final ClientRegistrationRepository repo;
    private final CustomAuthenticationSuccessHandler handler;
    private final UsersJwtAuthenticationFilter jwtAuthenticationFilter;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    public SecurityConfig(
        ClientRegistrationRepository repo,
        CustomAuthenticationSuccessHandler handler,
        UsersJwtAuthenticationFilter jwtAuthenticationFilter,
        JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint
    ) {
        this.repo = repo;
        this.handler = handler;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
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
                .successHandler(handler)
		//.failureHandler(handler) // TODO
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
	        UsernamePasswordAuthenticationFilter.class)
            .exceptionHandling(e -> e
                .authenticationEntryPoint(jwtAuthenticationEntryPoint));

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
            // リクエストキャッシュ機能 無効
            .requestCache(requestCache -> requestCache.disable())
            // サーブレットAPI連携（isUserInRole() 等） 無効
            .servletApi(servletApi -> servletApi.disable());
    }
}
