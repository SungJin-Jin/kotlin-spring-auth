package com.sc.security.handler

import com.sc.security.client.UserClient
import com.sc.security.datas.inout.Register
import feign.Feign
import feign.gson.GsonDecoder
import feign.gson.GsonEncoder
import org.hamcrest.Matchers
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThat
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.core.env.Environment
import org.springframework.test.context.junit4.SpringRunner

@RunWith(SpringRunner::class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class UserHandlerTest {

    @Autowired
    lateinit var environment: Environment

    lateinit var userClient: UserClient

    private fun <T> buildClient(type: Class<T>): T {
        val randomServerPort = environment.getProperty("local.server.port")?.toInt()

        return Feign.builder()
                .encoder(GsonEncoder())
                .decoder(GsonDecoder())
                .target(type, "http://localhost:$randomServerPort")
    }

    @Before
    fun setUp() {
        userClient = buildClient(UserClient::class.java)
    }

    @Test
    fun test_generate_token_when_user_register() {
        val register = userClient.register(Register(username = "tddda", email = "tddda@gmail.com", password = "tddda"))

        assertEquals("tddda", register.username)
        assertEquals("tddda@gmail.com", register.email)
        assertThat(register.token, Matchers.notNullValue())
    }
}
