package com.security.uaa.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.uaa.filter.JwtFilter;
import com.security.uaa.filter.RestAuthenticationFilter;
import com.security.uaa.service.UserDetailsPasswordServiceImpl;
import com.security.uaa.service.UserDetailsServiceImpl;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.MessageDigestPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Map;

@Slf4j
@EnableWebSecurity(debug = true)
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Autowired
    private UserDetailsPasswordServiceImpl userDetailsPasswordService;

    @Autowired
    private JwtFilter jwtFilter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(req -> req.mvcMatchers("/api/**").authenticated())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterAt(restAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                .formLogin(form ->
                        form.loginPage("/login")
                        .successHandler(jsonLoginSuccessHandler())
                        .failureHandler(jsonLoginFailureHandler()))

                .addFilterBefore(jwtFilter,UsernamePasswordAuthenticationFilter.class)
                .csrf(AbstractHttpConfigurer::disable)
//                .httpBasic(Customizer.withDefaults());
                .logout(logout -> logout.logoutUrl("/perform_logout"))
                .rememberMe(rememberMe -> rememberMe.tokenValiditySeconds( 30 * 24 * 3600 ).rememberMeCookieName("someKeyToRemember"));

    }

    private RestAuthenticationFilter restAuthenticationFilter() throws Exception {
        RestAuthenticationFilter filter = new RestAuthenticationFilter(objectMapper);
        filter.setAuthenticationSuccessHandler(jsonLoginSuccessHandler());
        filter.setAuthenticationFailureHandler(jsonLoginFailureHandler());
        filter.setAuthenticationManager(authenticationManager());
        filter.setFilterProcessesUrl("/authorize/login");
        return filter;
    }

    private AuthenticationSuccessHandler jsonLoginSuccessHandler() {
        return (req, res, auth) -> {
            ObjectMapper objectMapper = new ObjectMapper();
            res.setCharacterEncoding("UTF-8");
            res.setContentType(MediaType.APPLICATION_JSON_VALUE);
            res.setStatus(HttpStatus.OK.value());
            res.getWriter().println(objectMapper.writeValueAsString(auth));
            log.debug("认证成功");
        };
    }

    private AuthenticationFailureHandler jsonLoginFailureHandler() {
        return (req, res, exp) -> {
            res.setStatus(HttpStatus.UNAUTHORIZED.value());
            res.setContentType(MediaType.APPLICATION_JSON_VALUE);
            res.setCharacterEncoding("UTF-8");
            var errData = Map.of(
                    "title", "认证失败",
                    "details", exp.getMessage()
            );
            res.getWriter().println(objectMapper.writeValueAsString(errData));
        };
    }


    @Override
    public void configure(WebSecurity web) throws Exception {
        web
                .ignoring()
                .antMatchers("/public/**","/h2-console/**", "/authorize/**")
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        auth.userDetailsService(userDetailsService)
                .userDetailsPasswordManager(userDetailsPasswordService)
                .passwordEncoder(passwordEncoder());

    }

    @Bean
    PasswordEncoder passwordEncoder(){
        // 默认编码算法的 Id
        var idForEncode = "bcrypt";
        // 要支持的多种编码器
        var encoders = Map.of(
                idForEncode, new BCryptPasswordEncoder(),
                "SHA-1", new MessageDigestPasswordEncoder("SHA-1")
        );
        return new DelegatingPasswordEncoder(idForEncode, encoders);
    }
}
