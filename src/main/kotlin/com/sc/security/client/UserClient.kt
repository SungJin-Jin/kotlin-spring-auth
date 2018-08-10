package com.sc.security.client

import com.sc.security.client.response.InLogin
import com.sc.security.client.response.InRegister
import com.sc.security.client.response.OutUser
import feign.Headers
import feign.RequestLine

@Headers("Content-Type: application/json")
interface UserClient {

    @RequestLine("POST /api/users")
    fun register(register: InRegister): OutUser

    @RequestLine("POST /api/users/login")
    fun login(login: InLogin): OutUser
}