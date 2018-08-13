package com.sc.security.security

import com.sc.security.service.UserService
import org.aspectj.lang.ProceedingJoinPoint
import org.aspectj.lang.annotation.Around
import org.aspectj.lang.annotation.Aspect
import org.aspectj.lang.annotation.Pointcut
import org.aspectj.lang.reflect.MethodSignature
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Component
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Aspect
@Component
class ApiKeySecuredAspect(@Autowired val userService: UserService) {

    companion object {
        private val LOG = LoggerFactory.getLogger(ApiKeySecuredAspect::class.java)
    }

    @Autowired
    var request: HttpServletRequest? = null

    @Pointcut(value = "execution(@com.sc.security.security.ApiKeySecured * *.*(..))")
    fun securedApiPointcut() = Unit

    @Around("securedApiPointcut()")
    @Throws(Throwable::class)
    fun aroundSecuredApiPointcut(joinPoint: ProceedingJoinPoint): Any? {
        if (request?.method == "OPTIONS") return joinPoint.proceed()

        val response = request?.getAttribute(ExposeResponseInterceptor.KEY) as HttpServletResponse

        val signature = joinPoint.signature as MethodSignature
        val method = signature.method
        val annotation = method.getAnnotation(ApiKeySecured::class.java)

        val apiKey = request?.getHeader("Authorization")?.replace("Token ", "")

        if (apiKey.isNullOrEmpty() && annotation.mandatory) {
            LOG.info("No Authorization part of the request header/parameters, returning {}.", HttpServletResponse.SC_UNAUTHORIZED)

            issueError(response)
            return null
        }

        // TODO : Check validate issues

        return null
    }

    private fun issueError(response: HttpServletResponse) {
        response.status = HttpServletResponse.SC_UNAUTHORIZED
        response.setHeader("Authorization", "You shall not pass without providing a valid API Key")
        response.writer.write("{\"errors\": {\"Authorization\": [\"You must provide a valid Authorization header.\"]}}")
        response.writer.flush()
    }

}