package com.example;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ShiroCredentialsMatcher extends HashedCredentialsMatcher {
    private final Logger logger = LoggerFactory.getLogger(ShiroCredentialsMatcher.class);

    /**
     * 进行密码比较
     *
     * @param token 用户传过来的原始密码
     * @param info  数据库中查出来的加密后的密码
     */
    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        // 如果密码有默认的加密方式就自己处理，否则调用父类的方法
        if (isEncrypt()) {
            // 拿到原始密码可以用自己的方式进行加密(这里直接调用父类的方法)
            String password = new String((char[]) token.getCredentials());
            // 这个是用户设置的，类型不定
            Object tokenHashedCredentials = hashProvidedCredentials(token, info);
            Object accountCredentials = getCredentials(info);
            return equals(tokenHashedCredentials, accountCredentials);
        } else {
            // 如果没有加密方式，直接比较
            Object tokenCredentials = getCredentials(token);
            Object accountCredentials = getCredentials(info);
            return equals(tokenCredentials, accountCredentials);
        }
    }

    private boolean isEncrypt() {
        return true;
    }
}
