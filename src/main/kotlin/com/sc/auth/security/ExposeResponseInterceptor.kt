package com.sc.auth.security

import org.springframework.web.servlet.handler.HandlerInterceptorAdapter
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class ExposeResponseInterceptor : HandlerInterceptorAdapter() {

    companion object {
        const val KEY = "spring.internal.httpServletResponse"
    }

    @Throws(ServletException::class)
    override fun preHandle(request: HttpServletRequest, response: HttpServletResponse, handler: Any): Boolean {
        request.setAttribute(KEY, response)
        return true
    }
}