package com.sc.auth.client

import com.sc.auth.datas.User
import com.sc.auth.datas.inout.Login
import com.sc.auth.datas.inout.Register
import feign.Headers
import feign.RequestLine

@Headers("Content-Type: application/json")
interface UserClient {

    @RequestLine("POST /api/users")
    fun register(register: Register): User

    @RequestLine("POST /api/users/login")
    fun login(login: Login): User
}