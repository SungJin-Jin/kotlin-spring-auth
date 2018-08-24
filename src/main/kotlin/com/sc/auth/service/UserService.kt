package com.sc.auth.service

import com.sc.auth.datas.User
import com.sc.auth.datas.inout.Login
import com.sc.auth.datas.inout.Register
import com.sc.auth.exception.InvalidLoginException
import com.sc.auth.security.TokenManager
import com.sc.auth.repository.UserRepository
import org.springframework.security.crypto.bcrypt.BCrypt
import org.springframework.stereotype.Service

@Service
class UserService(
        val userRepository: UserRepository,
        val tokenManager: TokenManager
) {

    private val currentUser = ThreadLocal<User>()

    fun register(register: Register): User {
        val user = User(
                username = register.username!!,
                email = register.email!!,
                password = BCrypt.hashpw(register.password, BCrypt.gensalt()),
                token = tokenManager.newToken(register.email!!)
        )

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


    fun updateToken(user: User): User {
        user.token = tokenManager.newToken(user.email)
        return userRepository.save(user)
    }

    fun existsByEmail(email: String) = userRepository.existsByEmail(email)

    fun findByToken(token: String): User? = userRepository.findByToken(token)

}