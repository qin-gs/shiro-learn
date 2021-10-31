package com.example;

import org.apache.commons.collections4.MapUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.LifecycleProcessor;

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
        Map<String, String> principal = ((Map<String, String>) principals.getPrimaryPrincipal());
        // 从数据库获取权限信息，依次加进去
        info.addStringPermissions(List.of(principal.get("permissions").split(",")));
        // 从数据库获取角色信息，依次加进去
        info.addRoles(List.of(principal.get("roles").split(",")));
        return info;
    }

    /**
     * 认证配置
     * 这个token是 subject.login(token) 传过来的
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        // 拿到用户名去数据库查密码
        String username = (String) token.getPrincipal();
        // 从数据库中获取当前用户的信息, 这里的密码是加密的
        Map<String, String> userInfo = getUserInfoFromDatabase(username);
        if (MapUtils.isEmpty(userInfo)) {
            throw new UnknownAccountException("找不到该用户");
        }
        // 取出来之后如果不为空，将数据作为 principal 传入 AuthenticationInfo, 第三个参数是 Realm 的名字
        // 设置一个盐值
        return new SimpleAuthenticationInfo(
                userInfo,
                userInfo.get("password"),
                ByteSource.Util.bytes(userInfo.get("salt")),
                getName()
        );
    }

    private Map<String, String> getUserInfoFromDatabase(String username) {
        return Map.of(
                "username", username,
                "password", "00b3187384f2708025074f28764a4a30", // 这个值是123456加密后的结果
                "salt", "salt",
                "age", "21",
                "address", "China",
                "permissions", "teacher:update,student:read", // 从数据库中拿到权限
                "roles", "teacher,student"
        );
    }

    public static void main(String[] args) {
        String password = "123456";
        String algorithm = "md5";
        String salt = "salt";
        int iterations = 2;
        SimpleHash hash = new SimpleHash(algorithm, password, salt, iterations);
        // 00b3187384f2708025074f28764a4a30
        System.out.println(hash);
    }
}
