package com.sc.auth.security

import com.sc.auth.service.UserService
import org.aspectj.lang.ProceedingJoinPoint
import org.aspectj.lang.annotation.Around
import org.aspectj.lang.annotation.Aspect
import org.aspectj.lang.annotation.Pointcut
import org.aspectj.lang.reflect.MethodSignature
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Component
import org.springframework.util.StringUtils
import org.springframework.web.bind.annotation.ResponseStatus
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Suppress("UNREACHABLE_CODE")
@Aspect
@Component
class ApiKeySecuredAspect(
        @Autowired val request: HttpServletRequest,
        @Autowired val userService: UserService,
        @Autowired val tokenManager: TokenManager

) {
    companion object {
        private val LOG = LoggerFactory.getLogger(ApiKeySecuredAspect::class.java)
    }

    @Pointcut(value = "execution(@com.sc.auth.security.ApiKeySecured * *.*(..))")
    fun securedApiPointcut() = Unit

    @Around("securedApiPointcut()")
    @Throws(Throwable::class)
    fun aroundSecuredApiPointcut(joinPoint: ProceedingJoinPoint): Any? {
        if (request.method == "OPTIONS") return joinPoint.proceed()

        val method = (joinPoint.signature as MethodSignature).method
        val annotation = method.getAnnotation(ApiKeySecured::class.java)
        val apiKey = getApiKey()
        val user = userService.findByToken(apiKey)

        if (isEmptyApiKey(apiKey, annotation)
                || (user == null && annotation.mandatory)
                || tokenManager.validToken(apiKey, user!!.email).not())
            return issueError()

        userService.setCurrentUser(user)

        return try {
            joinPoint.proceed().apply {
                userService.clearCurrentUser()

            }
        } catch (e: Throwable) {
            throwExceptionWithResponseStatus(e)
        }
    }

    fun isEmptyApiKey(apiKey: String, annotation: ApiKeySecured): Boolean {
        return when {
            apiKey.isEmpty() && annotation.mandatory -> {
                LOG.info("No Authorization part of the request header/parameters, returning {}.", HttpServletResponse.SC_UNAUTHORIZED)

                true
            }
            else -> false
        }
    }

    fun getApiKey(): String = request.getHeader("Authorization")

    private fun issueError(): HttpServletResponse {
        val response = request.getAttribute(ExposeResponseInterceptor.KEY) as HttpServletResponse

        return with(response) {
            status = HttpServletResponse.SC_UNAUTHORIZED
            setHeader("Authorization", "You shall not pass without providing a valid API Key")
            writer.write("{\"errors\": {\"Authorization\": [\"You must provide a valid Authorization header.\"]}}")
            writer.flush()

            this
        }
    }

    fun throwExceptionWithResponseStatus(e: Throwable) {
        val responseStatus = e.javaClass.getAnnotation(ResponseStatus::class.java)
        if (responseStatus != null) {
            LOG.error("ERROR accessing resource, reason: '{}', status: {}.",
                    if (StringUtils.isEmpty(e.message)) responseStatus.reason else e.message,
                    responseStatus.value
            )
        } else {
            LOG.error("ERROR accessing resource")
        }
        throw e
    }

}