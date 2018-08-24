package com.sc.auth.security

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import java.util.*

@Component
class TokenManager(
        @Value("\${jwt.secret}") val secret: String,
        @Value("\${jwt.issuer}") val issuer: String
) {
    companion object {
        private const val TOKEN_EXPIRATION = 10 * 24 * 60 * 60 * 1000
    }

    fun newToken(subject: String): String {
        return Jwts.builder()
                .setIssuedAt(Date())
                .setSubject(subject)
                .setIssuer(issuer)
                .setExpiration(Date(System.currentTimeMillis() + TOKEN_EXPIRATION))
                .signWith(SignatureAlgorithm.HS256, secret)
                .compact()
    }

    fun validToken(token: String, subject: String): Boolean {
        val claims = createClaims(token)
        return claims.subject == subject && claims.issuer == issuer && Date().before(claims.expiration)
    }

    private fun createClaims(token: String) = Jwts.parser().setSigningKey(secret).parseClaimsJws(token).body

}