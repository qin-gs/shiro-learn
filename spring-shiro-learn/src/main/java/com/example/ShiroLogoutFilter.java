package com.example;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.LogoutFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

public class ShiroLogoutFilter extends LogoutFilter {
    private final Logger logger = LoggerFactory.getLogger(ShiroLogoutFilter.class);

    @Override
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        logger.info("退出登录");
        Subject subject = SecurityUtils.getSubject();
        subject.logout();
        response.getWriter().println("logout success filter");
        return false;
    }
}
