package com.incrage.ao.users.controller;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.http.ResponseCookie;
import org.springframework.ui.Model;
import java.time.Duration;

import com.incrage.ao.common.JwtCookie;

@Controller
public class LogoutController {

    private final JwtCookie jwtCookie;

    public LogoutController(JwtCookie jwtCookie) {
        this.jwtCookie = jwtCookie;
    }

    @GetMapping("/login/oauth2/logout")
    public String logout(
            @RequestParam(value = "return_to", required = false)
	    String returnTo,
            HttpServletResponse response,
            Model model ) {

	// 1. JWT Cookie を削除。
        jwtCookie.delete(response);        

	// 2. return_to があれば設定。
	if (returnTo != null && !returnTo.isBlank())
            model.addAttribute("return_to", returnTo);

	// 3. テンプレートを返す。
	return "logged-out"; // templates/logged-out.html を表示
    }
}
