package com.security.uaa.rest;

import com.security.uaa.domain.Auth;
import com.security.uaa.dto.LoginDto;
import com.security.uaa.dto.UserDto;
import com.security.uaa.resource.AppProperties;
import com.security.uaa.service.UserService;
import com.security.uaa.util.JwtUtil;
import org.h2.util.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

@RestController
@RequestMapping("authorize")
public class AuthorizeResource {

    @Autowired
    private UserService userService;

    @Autowired
    private AppProperties appProperties;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("register")
    private UserDto register(@Valid @RequestBody UserDto userDto){
        return userDto;
    }

    @PostMapping("token")
    public Auth token(@Validated @RequestBody LoginDto loginDto){
        return userService.login(loginDto.getUsername(),loginDto.getPassword());
    }

    @PostMapping("token/refresh")
    public Auth refreshToken(@RequestParam String refreshToken,HttpServletRequest request){

        var header = request.getHeader(appProperties.getJwt().getHeader());
        if (StringUtils.isNullOrEmpty(header)){
            throw new AccessDeniedException("Bad Credentials");
        }

        var accessToken = header.replace(appProperties.getJwt().getPrefix(),"");
        if (jwtUtil.validateRefreshToken(refreshToken) && jwtUtil.validateWithoutExpiration(accessToken)){
            return new Auth(jwtUtil.buildAccessTokenWithRefreshToken(refreshToken),refreshToken);
        }

        throw new AccessDeniedException("Bad Credentials");

    }

}
