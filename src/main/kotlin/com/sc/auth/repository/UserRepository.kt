package com.sc.auth.repository

import com.sc.auth.datas.User
import org.springframework.data.repository.CrudRepository
import org.springframework.stereotype.Repository

@Repository
interface UserRepository : CrudRepository<User, Long> {
    fun existsByEmail(email: String): Boolean

    fun existsByUsername(username: String): Boolean

    fun findByEmail(email: String): User?

    fun findByToken(token: String): User?

}