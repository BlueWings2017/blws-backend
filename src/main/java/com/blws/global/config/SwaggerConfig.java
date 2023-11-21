package com.blws.global.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import springfox.documentation.RequestHandler;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.*;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spi.service.contexts.SecurityContext;
import springfox.documentation.spring.web.plugins.Docket;

import java.util.Arrays;
import java.util.List;

@Configuration
public class SwaggerConfig {

    private ApiInfo getApiInfo(){
        return new ApiInfoBuilder()
                .title("LS MES")
                .description("LS MES API")
                .contact(new Contact("MES Swagger","",""))
                .version("1.0")
                .build();
    }

    @Bean
    public Docket commonApi(){
        return new Docket(DocumentationType.OAS_30)
                .apiInfo(this.getApiInfo())
                .securityContexts(Arrays.asList(this.securityContext()))
                .securitySchemes(Arrays.asList(this.apiKey()))
                .useDefaultResponseMessages(false)
                .select()
                .apis(RequestHandlerSelectors.basePackage("com.blws"))
                .paths(PathSelectors.any())
                .build();
    }

    private ApiKey apiKey() {
        return new ApiKey("authorization", "authorization", "header");
    }

    private SecurityContext securityContext() {
        return springfox
                .documentation
                .spi.service
                .contexts
                .SecurityContext
                .builder()
                .securityReferences(defaultAuth()).forPaths(PathSelectors.any()).build();
    }

    List<SecurityReference> defaultAuth() {
        AuthorizationScope authorizationScope = new AuthorizationScope("global", "accessEverything");
        AuthorizationScope[] authorizationScopes = new AuthorizationScope[1];
        authorizationScopes[0] = authorizationScope;
        return Arrays.asList(new SecurityReference("authorization", authorizationScopes));
    }
}
