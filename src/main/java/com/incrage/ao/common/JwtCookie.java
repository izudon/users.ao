package com.incrage.ao.common;
    
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

@Component
public class JwtCookie {

    public static final String COOKIE_NAME = "JWT_TOKEN";

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
        Cookie cookie = new Cookie(COOKIE_NAME, jwt);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(3600); // 1時間など適宜
        response.addCookie(cookie);
    }
}
