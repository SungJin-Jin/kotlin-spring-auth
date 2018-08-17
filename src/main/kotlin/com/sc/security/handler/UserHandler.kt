package com.sc.security.handler

import com.sc.security.datas.User
import com.sc.security.datas.inout.Login
import com.sc.security.datas.inout.Register
import com.sc.security.exception.ForbiddenRequestException
import com.sc.security.exception.InvalidException
import com.sc.security.exception.InvalidLoginException
import com.sc.security.exception.InvalidRequest
import com.sc.security.repository.UserRepository
import com.sc.security.security.ApiKeySecured
import com.sc.security.service.UserService
import org.springframework.security.crypto.bcrypt.BCrypt
import org.springframework.validation.BindException
import org.springframework.validation.Errors
import org.springframework.validation.FieldError
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import javax.validation.Valid

@RestController
class UserHandler(val repository: UserRepository, val service: UserService) {

    @PostMapping("/api/users")
    fun register(@Valid @RequestBody register: Register, errors: Errors): Any {
        InvalidRequest.check(errors)

        val errors = BindException(this, "")
        if (repository.existsByEmail(register.email!!)) errors.addError(createFiledError("email"))
        InvalidRequest.check(errors)

        val user = User(
                username = register.username!!,
                email = register.email!!,
                password = BCrypt.hashpw(register.password, BCrypt.gensalt())
        )
        user.token = service.newToken(user)

        return view(repository.save(user))
    }

    @PostMapping("/api/users/login")
    fun login(@Valid @RequestBody login: Login, errors: Errors): Any {
        InvalidRequest.check(errors)

        try {
            service.login(login)?.let {
                return view(service.updateToken(it))
            }
            return ForbiddenRequestException()
        } catch (e: InvalidLoginException) {
            val errors = BindException(this, "")
            errors.addError(FieldError("", e.field, e.error))
            throw InvalidException(errors)
        }
    }

    @ApiKeySecured
    @GetMapping("/api/user")
    fun currentUser() = view(service.currentUser())

    private fun createFiledError(filed: String): FieldError = FieldError("", filed, "already taken")

    private fun view(user: User) = mapOf("user" to user)
}