package com.sc.auth.controller

import com.sc.auth.datas.User
import com.sc.auth.datas.inout.Login
import com.sc.auth.datas.inout.Register
import com.sc.auth.datas.inout.UpdatedUser
import com.sc.auth.exception.ForbiddenRequestException
import com.sc.auth.exception.InvalidException
import com.sc.auth.exception.InvalidLoginException
import com.sc.auth.exception.InvalidRequest
import com.sc.auth.security.ApiKeySecured
import com.sc.auth.service.UserService
import org.springframework.security.crypto.bcrypt.BCrypt
import org.springframework.validation.BindException
import org.springframework.validation.Errors
import org.springframework.validation.FieldError
import org.springframework.web.bind.annotation.*
import javax.validation.Valid

@RestController
class UserController(val service: UserService) {

    @PostMapping("/api/users")
    fun register(@Valid @RequestBody register: Register, errors: Errors): Any {
        InvalidRequest.check(errors)

        if (service.existsByEmail(register.email!!)) {
            InvalidRequest.check(BindException(this, "").apply {
                addError(createFiledError("email", "already taken"))
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

    @ApiKeySecured
    @PutMapping("/api/user")
    fun updateUser(@Valid @RequestBody user: UpdatedUser, errors: Errors): Any {
        InvalidRequest.check(errors)

        val currentUser = service.currentUser()

        InvalidRequest.check(BindException(this, "").apply {
            if (currentUser.email != user.email) {
                if (service.existsByEmail(user.email)) {
                    addError(createFiledError("email", "already taken"))
                }
            }
            if (currentUser.username != user.username) {
                if (service.existsByUsername(user.username)) {
                    addError(createFiledError("username", "already taken"))
                }
            }
        })

        return view(service.save(copyUser(currentUser, user)))
    }

    fun copyUser(currentUser: User, user: UpdatedUser): User {
        return currentUser.copy(
                email = user.email ?: currentUser.email,
                username = user.username ?: currentUser.username,
                password = BCrypt.hashpw(user.password, BCrypt.gensalt()),
                image = user.image ?: currentUser.image,
                bio = user.bio ?: currentUser.bio
        )
    }

    private fun createFiledError(field: String, defaultMessage: String = ""): FieldError = FieldError("", field, defaultMessage)

    private fun view(user: User) = mapOf("user" to user)
}