package com.sc.auth.service

import com.sc.auth.datas.User
import com.sc.auth.datas.inout.Login
import com.sc.auth.datas.inout.Register
import com.sc.auth.exception.InvalidLoginException
import com.sc.auth.repository.UserRepository
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.crypto.bcrypt.BCrypt
import org.springframework.stereotype.Service
import java.util.*

@Service
class UserService(
        val userRepository: UserRepository,
        @Value("\${jwt.secret}") val secret: String,
        @Value("\${jwt.issuer}") val issuer: String
) {

    private val currentUser = ThreadLocal<User>()

    fun register(register: Register): User {
        val user = User(
                username = register.username!!,
                email = register.email!!,
                password = BCrypt.hashpw(register.password, BCrypt.gensalt())
        )
        user.token = newToken(user)

        return userRepository.save(user)
    }

    fun login(login: Login): User? {
        val user = userRepository.findByEmail(login.email!!)
        if (BCrypt.checkpw(login.password, user?.password)) {
            return updateToken(user!!)
        }

        throw InvalidLoginException("password", "invalid password")
    }

    fun currentUser(): User = currentUser.get()

    fun setCurrentUser(user: User): User {
        currentUser.set(user)
        return user
    }

    fun clearCurrentUser() = currentUser.remove()

    fun newToken(user: User): String {
        return Jwts.builder()
                .setIssuedAt(Date())
                .setSubject(user.email)
                .setIssuer(issuer)
                .setExpiration(Date(System.currentTimeMillis() + 10 * 24 * 60 * 60 * 1000)) // 10 days
                .signWith(SignatureAlgorithm.HS256, secret)
                .compact()
    }

    fun updateToken(user: User): User {
        user.token = newToken(user)
        return userRepository.save(user)
    }

    fun findByToken(token: String): User? = userRepository.findByToken(token)

    fun validToken(token: String, user: User): Boolean {
        val claims = createClaims(token)
        return claims.subject == user.email && claims.issuer == issuer && Date().before(claims.expiration)
    }

    private fun createClaims(token: String) = Jwts.parser().setSigningKey(secret).parseClaimsJws(token).body
}