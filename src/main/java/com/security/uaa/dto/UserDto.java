package com.security.uaa.dto;

import lombok.Data;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Data
public class UserDto {

    @NotNull
    @NotBlank
    @Size(min = 4, max = 50, message = "用户名长度必须在4-50个字符之间")
    private String username;

    @NotNull
    private String password;

    private String matchingPassword;

    @NotNull
    @Email
    private String email;

    @NotNull
    @NotBlank
    @Size(min = 4, max = 50, message = "用户名长度必须在4-50个字符之间")
    private String name;


}
