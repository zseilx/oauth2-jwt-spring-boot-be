package com.practice.oauth2.config;

import static org.springframework.security.config.Customizer.withDefaults;

import java.util.Arrays;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.practice.oauth2.auth.CustomOAuth2UserService;
import com.practice.oauth2.auth.OAuth2AuthenticationFailureHandler;
import com.practice.oauth2.auth.OAuth2AuthenticationSuccessHandler;
import com.practice.oauth2.auth.OAuth2AuthorizationRequestBasedOnCookieRepository;
import com.practice.oauth2.jwt.AuthTokenProvider;
import com.practice.oauth2.jwt.RestAuthenticationEntryPoint;
import com.practice.oauth2.jwt.RoleType;
import com.practice.oauth2.jwt.TokenAccessDeniedHandler;
import com.practice.oauth2.jwt.TokenAuthenticationFilter;
import com.practice.oauth2.jwt.UserRefreshTokenRepository;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity(debug = true)
public class SecurityConfig {

	private final CorsProperties corsProperties;
	private final AppProperties appProperties;
	private final AuthTokenProvider tokenProvider;
	private final CustomOAuth2UserService oAuth2UserService;
	private final TokenAccessDeniedHandler tokenAccessDeniedHandler;
	private final UserRefreshTokenRepository userRefreshTokenRepository;

	/*
	 * UserDetailsService 설정
	 */
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
            .cors(withDefaults())
            .csrf(csrf -> csrf.disable())
            .formLogin(fm -> fm.disable())
            .httpBasic(hb -> hb.disable())
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .exceptionHandling(eh -> {
                eh.authenticationEntryPoint(new RestAuthenticationEntryPoint());
                eh.accessDeniedHandler(tokenAccessDeniedHandler);
            })
            .authorizeHttpRequests(ohr -> {
                ohr.requestMatchers(CorsUtils::isPreFlightRequest).permitAll();
                ohr.antMatchers("/api/**").hasAnyAuthority(RoleType.USER.getCode());
                ohr.antMatchers("/api/**/admin/**").hasAnyAuthority(RoleType.ADMIN.getCode());
                ohr.anyRequest().authenticated();
            })
            .oauth2Login(o2l -> {
                o2l.authorizationEndpoint().baseUri("/oauth2/authorization")
                        .authorizationRequestRepository(oAuth2AuthorizationRequestBasedOnCookieRepository());
                o2l.redirectionEndpoint().baseUri("/*/oauth2/code/*");
                o2l.userInfoEndpoint(uie -> uie.userService(oAuth2UserService));
                o2l.successHandler(oAuth2AuthenticationSuccessHandler());
                o2l.failureHandler(oAuth2AuthenticationFailureHandler());
            });
        
		http.addFilterBefore(tokenAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

		return http.build();
	}

	/*
	 * auth 매니저 설정
	 */
	@Bean
	protected AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
		return authConfig.getAuthenticationManager();
	}

	/*
	 * 토큰 필터 설정
	 */
	@Bean
	public TokenAuthenticationFilter tokenAuthenticationFilter() {
		return new TokenAuthenticationFilter(tokenProvider);
	}

    /*
    * 쿠키 기반 인가 Repository
    * 인가 응답을 연계 하고 검증할 때 사용.
    * */
	@Bean
	public OAuth2AuthorizationRequestBasedOnCookieRepository oAuth2AuthorizationRequestBasedOnCookieRepository() {
		return new OAuth2AuthorizationRequestBasedOnCookieRepository();
	}

    /*
    * Oauth 인증 성공 핸들러
    * */
	@Bean
	public OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler() {
		return new OAuth2AuthenticationSuccessHandler(tokenProvider, appProperties, userRefreshTokenRepository,
				oAuth2AuthorizationRequestBasedOnCookieRepository());
	}

    /*
     * Oauth 인증 실패 핸들러
     * */
	@Bean
	public OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler() {
		return new OAuth2AuthenticationFailureHandler(oAuth2AuthorizationRequestBasedOnCookieRepository());
	}

    /*
    * Cors 설정
    * */
	@Bean
	public UrlBasedCorsConfigurationSource corsConfigurationSource() {
		UrlBasedCorsConfigurationSource corsConfigSource = new UrlBasedCorsConfigurationSource();

		CorsConfiguration corsConfig = new CorsConfiguration();
		corsConfig.setAllowedHeaders(Arrays.asList(corsProperties.getAllowedHeaders().split(",")));
		corsConfig.setAllowedMethods(Arrays.asList(corsProperties.getAllowedMethods().split(",")));
		corsConfig.setAllowedOrigins(Arrays.asList(corsProperties.getAllowedOrigins().split(",")));
		corsConfig.setAllowCredentials(true);
		corsConfig.setMaxAge(corsConfig.getMaxAge());

		corsConfigSource.registerCorsConfiguration("/**", corsConfig);
		return corsConfigSource;
	}
}
