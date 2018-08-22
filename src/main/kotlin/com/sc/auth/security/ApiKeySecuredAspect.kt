package com.sc.auth.security

import com.sc.auth.datas.User
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

@Aspect
@Component
class ApiKeySecuredAspect(
        @Autowired val userService: UserService

) {
    companion object {
        private val LOG = LoggerFactory.getLogger(ApiKeySecuredAspect::class.java)
    }

    @Autowired var request: HttpServletRequest? = null

    @Pointcut(value = "execution(@com.sc.auth.security.ApiKeySecured * *.*(..))")
    fun securedApiPointcut() {

    }

    @Around("securedApiPointcut()")
    @Throws(Throwable::class)
    fun aroundSecuredApiPointcut(joinPoint: ProceedingJoinPoint): Any? {
        if (request?.method == "OPTIONS") return joinPoint.proceed()

        val response = request?.getAttribute(ExposeResponseInterceptor.KEY) as HttpServletResponse

        val method = (joinPoint.signature as MethodSignature).method
        val annotation = method.getAnnotation(ApiKeySecured::class.java)

        val apiKey = getApiKey()

        if (isEmptyApiKey(apiKey, annotation)) {
            issueError(response)
            return null
        }

        var user = userService.findByToken(apiKey)

        when {
            user == null && annotation.mandatory -> {
                LOG.info("No user with Authorization: {}, returning {}.", apiKey, HttpServletResponse.SC_UNAUTHORIZED)

                issueError(response)
                return null
            }
            userService.validToken(apiKey, user ?: User()).not() -> when {
                annotation.mandatory.not() && user == null -> user = User()
                else -> {
                    issueError(response)
                    return null
                }
            }
            else -> return null
        }

        userService.setCurrentUser(user)

        return try {
            val result = joinPoint.proceed()

            userService.clearCurrentUser()

            LOG.info("DONE accessing resource.")

            result
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

    fun getApiKey() = request?.getHeader("Authorization")?.replace("Token ", "") ?: ""

    private fun issueError(response: HttpServletResponse) {
        response.status = HttpServletResponse.SC_UNAUTHORIZED
        response.setHeader("Authorization", "You shall not pass without providing a valid API Key")
        response.writer.write("{\"errors\": {\"Authorization\": [\"You must provide a valid Authorization header.\"]}}")
        response.writer.flush()
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