package com.example.authentication;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.ExcessiveAttemptsException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@DisplayName("authentication")
public class AuthenticationTest {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationTest.class);

    @Test
    public void test() {
        // 获取Subject的principals 和 credentials
        UsernamePasswordToken token = new UsernamePasswordToken("username", "password");

        // 记住 和 认证 是互斥的
        token.setRememberMe(true);

        // 提交 principals 和 credentials
        Subject subject = SecurityUtils.getSubject();

        try {
            subject.login(token);
        } catch (UnknownAccountException | IncorrectCredentialsException
                | LockedAccountException | ExcessiveAttemptsException ex) {
            log.error(ex.getMessage());
        }
        // 任何现有的Session都将失效并且任何身份都将被取消关联
        // (例如，在网络应用中，RememberMe cookie 也将被删除)
        // 由于 Web 应用程序中记住的身份通常与 cookie 保持在一起，
        // 并且 cookie 只能在提交响应正文之前删除，
        // 因此强烈建议在调用subject.logout()之后立即将最终用户重定向到新视图或页面。
        // 这样可以保证所有与安全性有关的 cookie 都可以按预期删除。
        // 这是 HTTP cookie 的功能限制，而不是 Shiro 的限制。
        subject.logout();
    }


}
