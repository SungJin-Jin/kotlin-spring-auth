package com.sc.security.service

import com.sc.security.datas.inout.Login
import com.sc.security.datas.User
import com.sc.security.exception.InvalidLoginException
import com.sc.security.repository.UserRepository
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.crypto.bcrypt.BCrypt
import org.springframework.stereotype.Service
import java.util.*

@Service
class UserService(
        val userRepository: UserRepository,
        @Value("\${jwt.secrect}") val secrect: String,
        @Value("\${jwt.issuer}") val issuer: String
) {

    fun login(login: Login): User? {
        userRepository.findByEmail(login.email!!).let {
            if(BCrypt.checkpw(login.password, it.password)) {
                return updateToken(it)
            }
            throw InvalidLoginException("password", "invalid password")
        }
    }

    fun newToken(user: User): String {
        return Jwts.builder()
                .setIssuedAt(Date())
                .setSubject(user.email)
                .setIssuer(issuer)
                .setExpiration(Date(System.currentTimeMillis() + 10 * 24 * 60 * 60 * 1000)) // 10 days
                .signWith(SignatureAlgorithm.HS256, secrect)
                .compact()
    }

    fun updateToken(user: User): User {
        user.token = newToken(user)
        return userRepository.save(user)
    }
}