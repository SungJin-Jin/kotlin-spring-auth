package com.sc.auth

import com.sc.auth.security.ExposeResponseInterceptor
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.cache.annotation.EnableCaching
import org.springframework.cloud.openfeign.EnableFeignClients
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean
import org.springframework.validation.beanvalidation.MethodValidationPostProcessor
import org.springframework.web.servlet.config.annotation.CorsRegistry
import org.springframework.web.servlet.config.annotation.InterceptorRegistry
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer

@Configuration
@EnableCaching
@EnableFeignClients
@SpringBootApplication
class AuthApplication : WebMvcConfigurer {

    override fun addCorsMappings(registry: CorsRegistry) {
        registry.addMapping("/api/**")
                .allowedOrigins("*")
                .allowedMethods("*")
                .allowedHeaders("*")
                .allowCredentials(false)
                .maxAge(3600)

        super.addCorsMappings(registry)
    }

    override fun addInterceptors(registry: InterceptorRegistry) {
        registry.addInterceptor(exposeResponseInterceptor())
    }

    @Bean
    fun exposeResponseInterceptor(): ExposeResponseInterceptor = ExposeResponseInterceptor()

    @Bean
    fun methodValidationPostProcessor(): MethodValidationPostProcessor = MethodValidationPostProcessor().apply { setValidator(validator()) }

    @Bean
    fun validator(): LocalValidatorFactoryBean = LocalValidatorFactoryBean()
}

fun main(args: Array<String>) {
    runApplication<AuthApplication>(*args)
}
