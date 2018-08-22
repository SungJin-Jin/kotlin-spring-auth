package com.sc.auth.swagger

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry
import org.springframework.web.servlet.config.annotation.WebMvcConfigurationSupport
import springfox.documentation.builders.ApiInfoBuilder
import springfox.documentation.builders.PathSelectors
import springfox.documentation.builders.PathSelectors.regex
import springfox.documentation.builders.RequestHandlerSelectors
import springfox.documentation.service.*
import springfox.documentation.spi.DocumentationType
import springfox.documentation.spi.service.contexts.SecurityContext
import springfox.documentation.spring.web.plugins.Docket
import springfox.documentation.swagger.web.ApiKeyVehicle
import springfox.documentation.swagger.web.SecurityConfiguration
import springfox.documentation.swagger2.annotations.EnableSwagger2

@EnableSwagger2
@Configuration
class SwaggerConfig : WebMvcConfigurationSupport() {


    @Bean
    fun api(): Docket {
        return Docket(DocumentationType.SWAGGER_2)
                .select()
                .apis(RequestHandlerSelectors.basePackage("com.sc.auth.controller"))
                .paths(PathSelectors.any())
                .build()
                .apiInfo(apiInfo())
                .securityContexts(listOf(securityContext()))
                .securitySchemes(listOf(apiKey()))
    }

    @Bean
    fun security(): SecurityConfiguration {
        return SecurityConfiguration(null, null, null, null,
                "Bearer access_token", ApiKeyVehicle.HEADER, "Authorization", ",")
    }

    override fun addResourceHandlers(registry: ResourceHandlerRegistry) {
        registry.addResourceHandler("swagger-ui.html")
                .addResourceLocations("classpath:/META-INF/resources/")

        registry.addResourceHandler("/webjars/**")
                .addResourceLocations("classpath:/META-INF/resources/webjars/")
    }

    private fun apiInfo(): ApiInfo {
        return ApiInfoBuilder()
                .title("Spring Auth")
                .description("Practice spring auth with JWT")
                .license("Apache 2.0")
                .licenseUrl("http://www.apache.org/licenses/LICENSE-2.0.html")
                .termsOfServiceUrl("htpp://swagger.io/terms")
                .version("1.0.0")
                .contact(Contact("SungJin", "", "deskhi@nethru.co.kr"))
                .build()
    }

    private fun securityContext(): SecurityContext =
            SecurityContext.builder()
                    .securityReferences(listOf(defaultAuth()))
                    .forPaths(PathSelectors.regex("/*"))
                    .build()

    private fun defaultAuth(): SecurityReference =
            SecurityReference("Authorization", arrayOf(AuthorizationScope("global", "accessEverything")))

    private fun apiKey(): ApiKey = ApiKey("Authorization", "jwt", "header")
}