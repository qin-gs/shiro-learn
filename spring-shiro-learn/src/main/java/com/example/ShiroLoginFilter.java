package com.example;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.time.Instant;
import java.util.Objects;

public class ShiroLoginFilter extends FormAuthenticationFilter {

    private final Logger logger = LoggerFactory.getLogger(ShiroLoginFilter.class);
    /**
     * 记录登录失败错误次数的session名
     */
    private final String LOGIN_FAILED_NUM = "LOGIN_FAILED_NUM";
    /**
     * 验证码的session名
     */
    private final String VERIFY_CODE = "VERIFY_CODE";
    /**
     * 登录错误次数限制，多于该值之后会出现验证码
     */
    private final Integer LOGIN_FAILED_MAX_NUM = 3;


    @Override
    protected boolean onLoginSuccess(AuthenticationToken token, Subject subject, ServletRequest request, ServletResponse response) throws Exception {
        logger.info("登录成功");
        Subject currentUser = SecurityUtils.getSubject();
        Session session = currentUser.getSession();
        // 这个对象是用户传递的，类型不定
        Object principal = subject.getPrincipals().getPrimaryPrincipal();
        // 登录成功后可以设置一些属性
        session.setAttribute("login_time", Instant.now().toEpochMilli());
        response.getWriter().println("登录成功");
        return false;
    }

    @Override
    protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException e, ServletRequest request, ServletResponse response) {

        try {
            logger.info("登录失败");
            HttpSession session = ((HttpServletRequest) request).getSession();
            if (Objects.nonNull(session.getAttribute(LOGIN_FAILED_NUM))) {
                session.setAttribute(LOGIN_FAILED_NUM, ((int) session.getAttribute(LOGIN_FAILED_NUM)) + 1);
            } else {
                session.setAttribute(LOGIN_FAILED_NUM, 1);
            }
            if (((int) session.getAttribute(LOGIN_FAILED_NUM)) >= LOGIN_FAILED_MAX_NUM) {
                session.setAttribute(VERIFY_CODE, getVerifyCode());
            }
            response.getWriter().println("登录失败");
            return super.onLoginFailure(token, e, request, response);
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        return false;
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        logger.info("登录验证...");
        if (isLoginRequest(request, response)) {
            if (isLoginSubmission(request, response)) {
                logger.info("检测到登录提交, 执行登录...");
                String username = request.getParameter("username");
                String password = request.getParameter("password");
                // 插入登录日志
                return executeLogin(request, response);
            }
        }
        return false;
    }

    private String getVerifyCode() {
        return RandomStringUtils.random(4);
    }
}
