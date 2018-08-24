package com.sc.auth.controller

import com.sc.auth.datas.User
import com.sc.auth.datas.inout.Login
import com.sc.auth.datas.inout.Register
import com.sc.auth.exception.ForbiddenRequestException
import com.sc.auth.exception.InvalidException
import com.sc.auth.exception.InvalidLoginException
import com.sc.auth.exception.InvalidRequest
import com.sc.auth.security.ApiKeySecured
import com.sc.auth.service.UserService
import org.springframework.validation.BindException
import org.springframework.validation.Errors
import org.springframework.validation.FieldError
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import javax.validation.Valid

@RestController
class UserController(val service: UserService) {

    @PostMapping("/api/users")
    fun register(@Valid @RequestBody register: Register, errors: Errors): Any {
        InvalidRequest.check(errors)

        if (service.existsByEmail(register.email!!)) {
            InvalidRequest.check(BindException(this, "").apply {
                addError(createFiledError("email"))

            })
        }

        return view(service.register(register))
    }

    @PostMapping("/api/users/login")
    fun login(@Valid @RequestBody login: Login, errors: Errors): Any {
        InvalidRequest.check(errors)

        return try {
            service.login(login)?.let {
                return view(service.updateToken(it))
            }

            ForbiddenRequestException()
        } catch (e: InvalidLoginException) {
            InvalidException(BindException(this, "").apply { addError(FieldError("", e.field, e.error)) })
        }
    }

    @ApiKeySecured
    @GetMapping("/api/user")
    fun currentUser() = view(service.currentUser())

    private fun createFiledError(filed: String): FieldError = FieldError("", filed, "already taken")

    private fun view(user: User) = mapOf("user" to user)
}