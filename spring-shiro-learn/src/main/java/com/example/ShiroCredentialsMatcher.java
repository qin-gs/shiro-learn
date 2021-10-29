package com.example;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.tomcat.util.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

public class ShiroCredentialsMatcher extends HashedCredentialsMatcher {
    private final Logger logger = LoggerFactory.getLogger(ShiroCredentialsMatcher.class);

    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        // 如果密码有默认的加密方式就自己处理，否则调用父类的方法
        if (isEncrypt()) {
            String password = token.getCredentials().toString();
            // 这个是用户设置的，类型不定
            Object principal = info.getPrincipals().getPrimaryPrincipal();
            password = Base64.encodeBase64String(password.getBytes(StandardCharsets.UTF_8));
            return info.getCredentials().equals(password);
        } else {
            return super.doCredentialsMatch(token, info);
        }
    }

    private boolean isEncrypt() {
        return true;
    }
}
