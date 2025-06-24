package com.incrage.ao.common;
    
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.http.ResponseCookie;
import org.springframework.beans.factory.annotation.Value;
import java.time.Duration;
    
@Component
public class JwtCookie {

    public static final String COOKIE_NAME = "JWT_TOKEN";

    private final int cookieMaxAgeDay;

    public JwtCookie(
        @Value("${app.jwt.cookie-max-age-day}") int cookieMaxAgeDay
    ) {
        this.cookieMaxAgeDay = cookieMaxAgeDay;
    }

    // JWT を Cookie から取り出す
    public String getToken(HttpServletRequest request) {
        if (request.getCookies() == null) {
            return null;
        }
        for (Cookie cookie : request.getCookies()) {
            if (COOKIE_NAME.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    // JWT を Cookie にセットしてレスポンスに追加
    public void setToken(String jwt, HttpServletResponse response) {
	String cookie = ResponseCookie.from(COOKIE_NAME, jwt)
	    .path("/")
	    .httpOnly(true)
	    .secure(true)
	    .sameSite("None")
	    .maxAge(Duration.ofDays(cookieMaxAgeDay))
	    .build()
	    .toString();

	response.addHeader("Set-Cookie", cookie);
    }
}
