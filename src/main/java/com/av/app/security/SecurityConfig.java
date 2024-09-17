package com.av.app.security;

import com.av.app.auth.AuthService;
import com.av.app.user.entity.User;
import com.av.base.util.SpringBeanUtils;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import java.io.IOException;

@Slf4j
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private RsaKeyConfigProperties rsaKeyConfigProperties;
    private final UserDetailService userDetailsService;

    @Autowired
    public void setRsaKeyConfigProperties(RsaKeyConfigProperties rsaKeyConfigProperties) {
        this.rsaKeyConfigProperties = rsaKeyConfigProperties;
    }

    @Autowired
    public SecurityConfig(UserDetailService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Bean(value = "authManager")
    public AuthenticationManager authManager() {

        var authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return new ProviderManager(authProvider);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JwtAuthenticationProvider jwtAuthenticationProvider() {
        return new JwtAuthenticationProvider();
    }

    private static class JwtAuthenticationProvider implements AuthenticationProvider {
        @Override
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            return authentication;
        }

        @Override
        public boolean supports(Class<?> authentication) {
            return JwtAuthenticationToken.class.isAssignableFrom(authentication);
        }
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(rsaKeyConfigProperties.getPublicKey()).build();
    }

    @Bean
    public JwtEncoder jwtEncoder() {
        JWK jwk = new RSAKey.Builder(rsaKeyConfigProperties.getPublicKey()).privateKey(rsaKeyConfigProperties.getPrivateKey()).build();

        JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwks);
    }

    private static class JwtTokenFilter extends OncePerRequestFilter {
        @Override
        protected void doFilterInternal(HttpServletRequest request,
                                        @NotNull HttpServletResponse response,
                                        @NotNull FilterChain filterChain) throws ServletException, IOException {
            String token = request.getHeader("token");
            if (token != null) {
                AuthService authService = SpringBeanUtils.getBean(AuthService.class);
                JwtDecoder jwtDecoder = SpringBeanUtils.getBean(JwtDecoder.class);

                Jwt jwt = jwtDecoder.decode(token);
                User user = authService.validateUserByJwt(jwt);
                if (user == null) {
                    log.error("User in extract token not found.");
                } else
                    SecurityContextHolder.getContext().setAuthentication(new JsonWebTokensAuthentication(jwt, user));
            }
            filterChain.doFilter(request, response);
        }
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception {

        return http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer((oauth2) -> oauth2.jwt((jwt) -> jwt.decoder(jwtDecoder())))
                .authenticationManager(authManager())
                .userDetailsService(userDetailsService)
                .httpBasic(Customizer.withDefaults())
                .addFilterBefore(new JwtTokenFilter(), UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}
