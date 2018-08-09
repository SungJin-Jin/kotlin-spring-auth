package com.sc.security.repository

import com.sc.security.datas.User
import org.springframework.data.repository.CrudRepository
import org.springframework.stereotype.Repository

@Repository
interface UserRepository: CrudRepository<User, Long> {
    fun existsByEmail(email: String): Boolean
    fun existsByUsername(username: String): Boolean
}