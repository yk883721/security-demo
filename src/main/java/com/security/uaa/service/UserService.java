package com.security.uaa.service;

import com.security.uaa.domain.Auth;
import com.security.uaa.repository.UserRepo;
import com.security.uaa.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PostMapping;

@Service
public class UserService {

    @Autowired
    private UserRepo userRepo;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

    public Auth login(String username, String password){
        return userRepo.findOptionalByUsername(username)
                .filter(user -> passwordEncoder.matches(password,user.getPassword()))
                .map(user -> new Auth(jwtUtil.createAccessToken(user),jwtUtil.createRefreshToken(user)))
                .orElseThrow(() -> new AccessDeniedException("用户名密码错误"));
    }



}
