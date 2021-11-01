package com.example;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

    @PostMapping("/login")
    public String login(String username, String password) {
        // 这里直接给原始的账号密码，shiro会自己加密
        UsernamePasswordToken token = new UsernamePasswordToken(username, password);
        Subject subject = SecurityUtils.getSubject();
        // 这个token会被传到 Realm#doGetAuthenticationInfo 方法中
        subject.login(token);
        return "login success";
    }

    @GetMapping("teacher")
    public String teacher() {
        return "teacher";
    }

    @GetMapping("student")
    public String student() {
        return "student";
    }
}
