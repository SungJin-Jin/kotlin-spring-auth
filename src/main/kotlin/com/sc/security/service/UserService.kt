package com.sc.security.service

import com.sc.security.datas.User
import com.sc.security.repository.UserRepository
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Service
import java.util.*

@Service
class UserService(
        val userRepository: UserRepository,
        @Value("\${jwt.secrect}") val secrect: String,
        @Value("\${jwt.issuer}") val issuer: String
) {

    fun newToken(user: User): String {
        return Jwts.builder()
                .setIssuedAt(Date())
                .setSubject(user.email)
                .setIssuer(issuer)
                .setExpiration(Date(System.currentTimeMillis() + 10 * 24 * 60 * 60 * 1000)) // 10 days
                .signWith(SignatureAlgorithm.HS256, secrect)
                .compact()
    }
}