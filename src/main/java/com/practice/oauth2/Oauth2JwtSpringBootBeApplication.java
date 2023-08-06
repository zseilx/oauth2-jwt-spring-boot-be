package com.practice.oauth2;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

import com.practice.oauth2.config.AppProperties;
import com.practice.oauth2.config.CorsProperties;

@SpringBootApplication
@EnableConfigurationProperties({
    CorsProperties.class,
    AppProperties.class
})
public class Oauth2JwtSpringBootBeApplication {

	public static void main(String[] args) {
		SpringApplication.run(Oauth2JwtSpringBootBeApplication.class, args);
	}

}
