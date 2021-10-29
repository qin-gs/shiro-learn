package com.example;

import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.session.Session;
import org.apache.shiro.web.servlet.ShiroHttpServletRequest;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.Serializable;
import java.util.Collection;

public class ShiroSessionManager extends DefaultWebSessionManager {
    protected final Logger logger = LoggerFactory.getLogger(ShiroSessionManager.class);

    public ShiroSessionManager() {
        super();
        setGlobalSessionTimeout(30 * 60 * 1000);
    }

    @Override
    protected Serializable getSessionId(ServletRequest request, ServletResponse response) {
        String sessionId = WebUtils.toHttp(request).getHeader("Authorization");
        if (StringUtils.isNotEmpty(sessionId)) {
            request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_SOURCE, "stateless request");
            request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID, sessionId);
            request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_IS_VALID, Boolean.TRUE);
            return sessionId;
        }
        return super.getSessionId(request, response);
    }

    public Collection<Session> getAllSessions() {
        return this.getSessionDAO().getActiveSessions();
    }
}
