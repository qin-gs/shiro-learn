package com.example;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;

public class ShiroRealm extends AuthorizingRealm {

    protected Logger logger = LoggerFactory.getLogger(ShiroRealm.class);

    /**
     * 权限配置
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        logger.info("权限信息加载...");
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        // 用户配置，类型不定
        Object principal = principals.getPrimaryPrincipal();
        // 从数据库获取权限信息，依次加进去
        info.addStringPermissions(List.of("admin", "guest"));
        // 从数据库获取角色信息，依次加进去
        info.addRoles(List.of("student", "teacher"));
        return info;
    }

    /**
     * 认证配置
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        // 拿到用户名去数据库查密码
        String username = (String) token.getPrincipal();
        // String pwd = ((String) token.getCredentials()); // 这个密码是前端传过来的
        // 从数据库中获取当前用户的信息
        // select username, password from account where username = :username;
        Map<String, String> userInfo = getUserInfoFromDatabase(username);
        // 取出来之后如果不为空，将数据作为 principal 传入 AuthenticationInfo
        return new SimpleAuthenticationInfo(userInfo, userInfo.get("password"), getName());
    }

    private Map<String, String> getUserInfoFromDatabase(String username) {
        return Map.of(
                "username", "qqq",
                "password", "123456",
                "age", "21",
                "address", "China"
        );
    }
}
