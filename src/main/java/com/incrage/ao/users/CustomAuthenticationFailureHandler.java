package com.incrage.ao.users;

import java.net.URLEncoder;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security
    .web.authentication.AuthenticationFailureHandler;
import org.springframework.security
    .core.AuthenticationException;
import org.springframework.stereotype.Component;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import java.io.IOException;

@Component
public class CustomAuthenticationFailureHandler
    implements AuthenticationFailureHandler {

    public static final String ERROR_PAGE
	= "https://onboading-test.ao.incrage.com/";
    
    private final TemplateEngine templateEngine;

    public CustomAuthenticationFailureHandler(TemplateEngine templateEngine) {
        this.templateEngine = templateEngine;
    }

    @Override
    public void onAuthenticationFailure(
	HttpServletRequest request,
	HttpServletResponse response,
	AuthenticationException exception
    ) throws IOException, ServletException {

        // 1. セッションから return_to を復元 -> Thymeleaf コンテキストへ。
	Context context = new Context();
        HttpSession session = request.getSession(false);

        if (session != null) {
	    String returnTo = (String) session.getAttribute("return_to");
	    if( returnTo != null )
		context.setVariable("return_to", returnTo);
            session.invalidate(); // セッションを破棄
        }

	// 2. Thymeleaf テンプレートでページを生成
	String html = templateEngine.process("unauthorized", context);
	
	// 3. Thymeleaf テンプレートで返す
	response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
	response.setContentType("text/html; charset=UTF-8");
	response.getWriter().write(html);
    }
}
