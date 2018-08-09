package com.sc.security.handler

import com.sc.security.datas.Register
import com.sc.security.datas.User
import com.sc.security.exception.InvalidRequest
import com.sc.security.repository.UserRepository
import com.sc.security.service.UserService
import org.springframework.security.crypto.bcrypt.BCrypt
import org.springframework.validation.BindException
import org.springframework.validation.Errors
import org.springframework.validation.FieldError
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import javax.validation.Valid

@RestController
class UserHandler(
        val repository: UserRepository,
        val service: UserService
) {

    @PostMapping("api/users")
    fun register(@Valid @RequestBody register: Register, errors: Errors): Any {
        InvalidRequest.check(errors)

        val errors = BindException(this, "")
        checkUserAvailability(errors, register.email, register.username)
        InvalidRequest.check(errors)

        val user = User(username = register.username!!, email = register.email!!, password = BCrypt.hashpw(register.password, BCrypt.gensalt()))
        user.token = service.newToken(user)

        return mapOf("user" to user)
    }

    private fun checkUserAvailability(errors: BindException, email: String?, username: String?) {
        email?.apply {
            if (repository.existsByEmail(this)) errors.addError(FieldError("", "email", "already taken"))
        }

        username?.apply {
            if (repository.existsByUsername(this)) errors.addError(FieldError("", "username", "already taken"))
        }
    }
}