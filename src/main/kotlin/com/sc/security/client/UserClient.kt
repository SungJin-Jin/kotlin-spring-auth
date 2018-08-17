package com.sc.security.client

import com.sc.security.datas.User
import com.sc.security.datas.inout.Login
import com.sc.security.datas.inout.Register
import feign.Headers
import feign.RequestLine

@Headers("Content-Type: application/json")
interface UserClient {

    @RequestLine("POST /api/users")
    fun register(register: Register): User

    @RequestLine("POST /api/users/login")
    fun login(login: Login): User
}