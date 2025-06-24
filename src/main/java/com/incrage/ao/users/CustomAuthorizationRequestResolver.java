package com.incrage.ao.users;

import java.util.Set;
import java.net.URI;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security
    .authentication.AbstractAuthenticationToken;
import org.springframework.security
    .oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security
    .oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security
    .oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security
    .oauth2.core.endpoint.OAuth2AuthorizationRequest;

/**
 * ベースとなるクラス DefaultOAuth2AuthorizationRequestResolver の
 * 動きが基本的に怪しいので：
 * - getRedirectUri() で
 *   /login/oauth2/... が返るはずが
 *   /authorization/oauth2/... が返っているよう。
 * - 明示的に registrationId を指定して作成した時にしかこれを参照できないよう。
 * 不可解な点が多いと思いますがご了承ください。
 */
public class CustomAuthorizationRequestResolver
    implements OAuth2AuthorizationRequestResolver {

    private final OAuth2AuthorizationRequestResolver defaultResolver;

    public CustomAuthorizationRequestResolver
	(ClientRegistrationRepository repo) {
        this.defaultResolver
	    = new DefaultOAuth2AuthorizationRequestResolver(repo, "/dummy");
    }

    @Override // ２引数版 -> １引数版 呼ぶだけ
    public OAuth2AuthorizationRequest resolve
	(HttpServletRequest request, String registrationId) {
        return resolve(request);
    }

    @Override // １引数版
    public OAuth2AuthorizationRequest resolve
	(HttpServletRequest request) {

	// 1. 非該当は非処理
	String path = URI.create(request.getRequestURI()).getPath();
	if (!path.startsWith("/enter/")) return null;

	// 2. registrationId の取得
	String registrationId = path.substring(path.lastIndexOf("/") + 1);
	
	// 3. 認証成功後の戻り先をセッションに記憶
        String returnTo = request.getParameter("return_to");
        if (returnTo != null && !returnTo.isBlank()) {
            HttpSession session = request.getSession(true); // なければ作成
            session.setAttribute("return_to", returnTo);
        }

	// 4. リダイレクトバックポイントのURLを差し替え

	// オリジナルの取得
	OAuth2AuthorizationRequest original
	    = defaultResolver.resolve(request, registrationId);

	// ホスト名
	String host = request.getHeader("X-Forwarded-Host");
	if (host == null || host.isBlank())
	    host = request.getHeader("Host");

	// ホスト名の変更とパス先頭への /users 挿入 および https:// 化
	String redirectUri
	    = "https://" + host
	    + "/users/login/oauth2/code/" + registrationId;

	// ビルドして返す
	return OAuth2AuthorizationRequest.from(original)
	    .redirectUri(redirectUri)
	    .build();
    }
}
