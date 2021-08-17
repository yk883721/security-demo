package com.security.uaa.rest;

import com.security.uaa.dto.UserDto;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
@RequestMapping("authorize")
public class AuthorizeResource {

    @PostMapping("register")
    private UserDto register(@Valid @RequestBody UserDto userDto){
        return userDto;
    }

}
