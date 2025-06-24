package com.incrage.ao.common;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.List;
import java.util.Date;
import java.util.Map;

@Component
public class JwtProvider {

    private final Key primaryKey;
    private final Key spareKey;
    private final long expirationMs;

    public JwtProvider(
        @Value("${app.jwt.secret-key}") String secret,
        @Value("${app.jwt.secret-key-spare}") String spare,
        @Value("${app.jwt.expiration-ms}") long expirationMs
    ) {
        this.primaryKey
	    = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.spareKey
	    = Keys.hmacShaKeyFor(spare.getBytes(StandardCharsets.UTF_8));
        this.expirationMs = expirationMs;
    }

    /**
     * JWT を検証後にそのペイロードを返す。
     *
     * 戻り値は Claims オブジェクトで、これは、
     * .getSubject() .getIssuer() .get("someKey")
     * などとしてペイロードの中を読むことができる。
     *
     * ノーエラーの場合は Claims を返すが、
     * 有効期限切れなどの場合は原因別に、
     * JwtException のサブクラスとして返ってくる。
     *
     * ExpiredJwtException PrematureJwtException （最後の２つ）の場合は、
     * エラーオブジェクトから e.getClaims() として Claims を取得できる。
     * 期限切れ等であってもペイロードの中を読むことができるということ。
     * ただしフォーマットや署名が正しければである。
     * 
     * 呼出元ではこれらを場合分けするなどして、適宜処理に用いること。
     *
     * @param token JWTトークン文字列。
     * @return Claims JWTのペイロードを表現するオブジェクト。
     * @throws CompressionException - デコードできない。
     * @throws MalformedJwtException - フォーマットが JWT として正しくない。
     * @throws SignatureException - 署名がおかしい（署名検証エラー）。
     * @throws ExpiredJwtException - exp 有効期限より今が後である。
     * @throws PrematureJwtException - nbf 有効開始より今が前である。
     */
    public Claims getClaims(String token) throws JwtException {
	List<Key> keys = List.of(primaryKey, spareKey);

	for (Key key : keys) {
	    try {
		return Jwts.parserBuilder()
		    .setSigningKey(key)
		    .build()
		    .parseClaimsJws(token)
		    .getBody();
	    } catch (SignatureException e) {
		continue; // 署名が違う → 次の鍵で試す
	    }
	}
	throw new SignatureException("Signature does not match any known key");
    }

    /**
     * 与えられた claims を使って JWT を生成する。
     * 現在は 文字列 subject のみ受け取る。
     *
     * @param subject サブジェクト文字列。
     * @return String JWTトークン文字列
     */
    public String setClaims(String subject) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + expirationMs);

        return Jwts.builder()
	    .setSubject(subject)
	    .setIssuedAt(now)
	    .setExpiration(expiry)
	    .signWith(primaryKey, SignatureAlgorithm.HS256)
	    .compact();
    }
}
