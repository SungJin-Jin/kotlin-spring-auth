package com.sc.security.security

import com.sc.security.datas.User
import com.sc.security.service.UserService
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

        val apiKey = getApiKey()

        if (validateApiKey(apiKey, annotation, response)) return null

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

        try {
            val result = joinPoint.proceed()

            userService.clearCurrentUser()

            LOG.info("DONE accessing resource.")

            return result
        } catch (e: Throwable) {
            val rs = e.javaClass.getAnnotation(ResponseStatus::class.java)
            if (rs != null) {
                LOG.error("ERROR accessing resource, reason: '{}', status: {}.",
                        if (StringUtils.isEmpty(e.message)) rs.reason else e.message,
                        rs.value)
            } else {
                LOG.error("ERROR accessing resource")
            }
            throw e
        }
    }

    fun validateApiKey(apiKey: String, annotation: ApiKeySecured, response: HttpServletResponse): Boolean {
        if (apiKey.isEmpty() && annotation.mandatory) {
            LOG.info("No Authorization part of the request header/parameters, returning {}.", HttpServletResponse.SC_UNAUTHORIZED)

            issueError(response)
            return true
        }
        return false
    }

    fun getApiKey() = request?.getHeader("Authorization")?.replace("Token ", "") ?: ""

    private fun issueError(response: HttpServletResponse) {
        response.status = HttpServletResponse.SC_UNAUTHORIZED
        response.setHeader("Authorization", "You shall not pass without providing a valid API Key")
        response.writer.write("{\"errors\": {\"Authorization\": [\"You must provide a valid Authorization header.\"]}}")
        response.writer.flush()
    }

}