package com.example.session;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.cache.ehcache.EhCacheManager;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.SessionListener;
import org.apache.shiro.session.mgt.DefaultSessionManager;
import org.apache.shiro.session.mgt.ExecutorServiceSessionValidationScheduler;
import org.apache.shiro.session.mgt.eis.MemorySessionDAO;
import org.apache.shiro.session.mgt.eis.RandomSessionIdGenerator;
import org.apache.shiro.session.mgt.eis.SessionIdGenerator;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.List;

@DisplayName("session")
public class SessionTest {

    Subject subject = SecurityUtils.getSubject();

    @Test
    public void test(HttpServletRequest request) {
        // 以下两种方式效果相同
        Session session = subject.getSession(); // 如果没有session，根据参数确定是否创建
        HttpSession s = request.getSession();

        session.setAttribute("someKey", "someValue");

        // 可以在 SecurityManager 中设置 SessionManager
        DefaultSecurityManager sManager = new DefaultSecurityManager();

        // session 管理
        DefaultSessionManager manager = new DefaultSessionManager();
        // 默认超时时间 30 分钟
        manager.setGlobalSessionTimeout(60 * 60 * 1000); // 可以自定义为一小时

        sManager.setSessionManager(manager);
        // SessionListener 监听会话事件
        SessionListener listener = new MySessionListener();
        manager.setSessionListeners(List.of(listener));

        // session 操作
        MemorySessionDAO sessionDAO = new MemorySessionDAO();
        manager.setSessionDAO(sessionDAO);

        // session缓存配置
        EhCacheManager cManager = new EhCacheManager();
        sManager.setCacheManager(cManager);

        // session id 生成
        SessionIdGenerator generator = new RandomSessionIdGenerator();
        sessionDAO.setSessionIdGenerator(generator);

        // session验证，删除 orphans(没有退出，直接关闭浏览器)
        ExecutorServiceSessionValidationScheduler scheduler = new ExecutorServiceSessionValidationScheduler();
        scheduler.setInterval(60 * 60 * 1000); // 设置 验证间隔
        manager.setSessionValidationScheduler(scheduler);
        // 禁用会话验证
        manager.setSessionValidationSchedulerEnabled(false);
        // 禁用无效会话的删除，需要自己手动删除
        manager.setDeleteInvalidSessions(false);

        UsernamePasswordToken token = new UsernamePasswordToken("username", "password");
        token.setRememberMe(true);
        subject.login(token);

        CookieRememberMeManager cookieManager = new CookieRememberMeManager();
        sManager.setRememberMeManager(cookieManager);


    }
}
