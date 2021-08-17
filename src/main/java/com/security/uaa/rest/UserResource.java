package com.security.uaa.rest;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;


@RestController
@RequestMapping("api")
public class UserResource {

    @GetMapping("greeting")
    public String greeting(){
        return "hello World";
    }

    @GetMapping("principal")
    public Object getPrincipal(Principal principal){
        return principal;
    }

}
