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

    public static final String COOKIE_DOMAIN = "incrage.com";

    private final int cookieMaxAgeDay;

    public JwtCookie(
        @Value("${app.jwt.cookie-max-age-day}") int cookieMaxAgeDay
    ) {
        this.cookieMaxAgeDay = cookieMaxAgeDay;
    }

    // JWT を Cookie から取り出す
    public String get(HttpServletRequest request) {
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

    // JWT を Cookie に追加（レスポンスにセット）
    public void set(String jwt, HttpServletResponse response) {
	String cookie = baseCookie(jwt)
	    .maxAge(Duration.ofDays(cookieMaxAgeDay))
	    .build()
	    .toString();
	response.addHeader("Set-Cookie", cookie);
    }

    // JWT を Cookie から削除（期限が今の Cookie をレスポンスにセット）
    public void delete(HttpServletResponse response) {
	String cookie = baseCookie("")
	    .maxAge(Duration.ZERO)
	    .build()
	    .toString();
	response.addHeader("Set-Cookie", cookie);
    }

    // 期限以外の部分を共通にビルドする private 関数
    private ResponseCookie.ResponseCookieBuilder baseCookie(String baseStr) {
	return ResponseCookie.from(COOKIE_NAME, baseStr)
	    .domain(COOKIE_DOMAIN)
	    .path("/")
	    .httpOnly(true)
	    .secure(true)
	    .sameSite("None");
    }
}
