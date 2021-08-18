package com.security.uaa.filter;

import com.security.uaa.resource.AppProperties;
import com.security.uaa.util.CollectionUtil;
import com.security.uaa.util.JwtUtil;
import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Component
public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    private AppProperties appProperties;

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (checkJwtToken(request)){
            String token = request.getHeader(appProperties.getJwt().getHeader())
                    .replace(appProperties.getJwt().getPrefix(),"");
            jwtUtil.parseClaims(token, JwtUtil.key )
                    .filter(claims -> claims.get("authorities") != null)
                    .ifPresentOrElse(
                           this::setupSpringAuthentication,
                            SecurityContextHolder::clearContext
                    );
        }
        filterChain.doFilter(request,response);
    }

    private void setupSpringAuthentication(Claims claims) {
        List<?> list = CollectionUtil.convertObjectToList(claims.get("authorities"));
        List<SimpleGrantedAuthority> authorities = list.stream()
                .map(String::valueOf)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        var authentication = new UsernamePasswordAuthenticationToken(claims.get("username"),null,authorities);
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private boolean checkJwtToken(HttpServletRequest request) {

        String header = request.getHeader(appProperties.getJwt().getHeader());
        return header != null && header.startsWith(appProperties.getJwt().getPrefix());

    }

}
