package com.security.uaa.resource;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "mooc")
public class AppProperties {

    private Jwt jwt = new Jwt();


    @Getter
    @Setter
    public static class Jwt{

        private String header = "Authorization"; // HTTP 报头的认证字段的 key

        private String prefix = "Bearer "; // HTTP 报头的认证字段的值的前缀

        private long accessTokenExpireTime = 60 * 1000L;

        private long refreshTokenExpireTime = 60 * 1000L;

    }

}
