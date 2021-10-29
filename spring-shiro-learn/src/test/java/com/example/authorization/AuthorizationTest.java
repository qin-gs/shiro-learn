package com.example.authorization;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresGuest;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.apache.shiro.authz.permission.WildcardPermission;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Objects;
import java.util.Set;

@DisplayName("authorization 授权")
public class AuthorizationTest {

    Subject subject = SecurityUtils.getSubject();

    @Test
    public void test() {

        // 查看用户是否有否个角色
        boolean hasRole = subject.hasRole("administrator");
        boolean[] hasRoles = subject.hasRoles(List.of("administrator", "student"));
        boolean hasAllRoles = subject.hasAllRoles(List.of("administrator", "student", "teacher"));

        // assert 确保用户有某个角色，否则会抛AuthorizationException异常(不需要自己手动抛异常)
        subject.checkRole("guest");
        subject.checkRoles(Set.of("administrator", "student"));

        // 权限检查
        // 通配符  资源类型:操作:id
        WildcardPermission permission = new WildcardPermission("book:read:id");
        boolean read = subject.isPermitted(permission);

        // assert 确保用户具有权限，否则会抛出异常
        subject.checkPermission(permission);
        subject.checkPermissions(List.of(permission, permission));

    }

    /**
     * 该注解要求当前用户在会话期间已经通过身份验证
     */
    @RequiresAuthentication
    public void authentication() {
        // @RequiresAuthentication 该注解的效果等同与如下代码
        if (!SecurityUtils.getSubject().isAuthenticated()) {
            throw new AuthorizationException();
        }
        // do something
    }

    /**
     * 该注解要求当前用户树guest
     */
    @RequiresGuest
    public void guest() {
        // 该注解的效果等同如下代码
        PrincipalCollection principals = subject.getPrincipals();
        if (principals != null && !principals.isEmpty()) {
            throw new AuthorizationException();
        }
        // subject is guaranteed to be a 'guest' here
        // do something
    }

    /**
     * 该注解要求当前主题被授予一个或多个权限，以便执行带注解的方法
     */
    @RequiresPermissions("account:create")
    public void permissions() {
        // 该注解的效果等同如下代码
        if (!subject.isPermitted("account:create")) {
            throw new AuthorizationException();
        }
        // do something
    }

    /**
     * 该注解要求当前用户具有所有指定的角色
     */
    @RequiresRoles(value = {"student"})
    public void roles() {
        if (subject.hasRole("student")) {
            throw new AuthorizationException();
        }
        // do something
    }

    /**
     * TODO
     */
    @RequiresUser
    public void user() {
        // 该注解效果等同如下代码
        PrincipalCollection principals = subject.getPrincipals();
        if (Objects.isNull(principals) || principals.isEmpty()) {
            throw new AuthorizationException();
        }
    }


}
