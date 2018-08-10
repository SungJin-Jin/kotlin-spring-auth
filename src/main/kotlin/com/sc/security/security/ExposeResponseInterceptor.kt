package com.sc.security.security

import org.springframework.web.servlet.handler.HandlerInterceptorAdapter
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class ExposeResponseInterceptor: HandlerInterceptorAdapter() {

    companion object {
        val KEY = "spring.internal.httpServletResponse"
    }

    @Throws
    override fun preHandle(request: HttpServletRequest, response: HttpServletResponse, handler: Any): Boolean {
        request.setAttribute(KEY, response)
        return true
    }
}