package at.davl.springBootRESTSecurity.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


// https://www.baeldung.com/spring-deprecated-websecurityconfigureradapter
//
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorizationManagerRequestMatcherRegistry ->
                        authorizationManagerRequestMatcherRegistry
                                .requestMatchers(HttpMethod.DELETE).hasRole("ADMIN")
                                //.requestMatchers("/admin/**").hasAnyRole("ADMIN")
                                //.requestMatchers("/user/**").hasAnyRole("USER", "ADMIN")

                                .requestMatchers("/api/v1/auth/**").permitAll()
                                //.requestMatchers("/api/v1/demo-controller").hasRole("USER")
                                .anyRequest().authenticated()
                        )
                //.httpBasic(Customizer.withDefaults())
                .sessionManagement(httpSecuritySessionManagementConfigurer ->
                        httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authenticationProvider(authenticationProvider)
                // JWT filter
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);


        return http.build();
    }
}
