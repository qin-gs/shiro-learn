package com.example;

import org.apache.commons.collections4.MapUtils;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.session.SessionListener;
import org.apache.shiro.session.mgt.DefaultSessionManager;
import org.apache.shiro.session.mgt.eis.EnterpriseCacheSessionDAO;
import org.apache.shiro.session.mgt.eis.JavaUuidSessionIdGenerator;
import org.apache.shiro.session.mgt.eis.SessionDAO;
import org.apache.shiro.session.mgt.eis.SessionIdGenerator;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.servlet.Filter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * shiro配置
 */
@Configuration
public class ShiroConfig {

    @Bean
    public AuthorizingRealm authorizingRealm() {
        ShiroRealm realm = new ShiroRealm();
        realm.setCredentialsMatcher(credentialsMatcher());
        return realm;
    }

    @Bean
    public DefaultSessionManager sessionManager() {
        DefaultWebSessionManager manager = new ShiroSessionManager();
        manager.setSessionListeners(List.of(sessionListener()));
        manager.setSessionIdCookie(sessionIdCookie());
        manager.setSessionDAO(sessionDAO());
        return manager;
    }

    @Bean
    public SessionListener sessionListener() {
        return new ShiroSessionListener();
    }

    @Bean
    public DefaultSecurityManager securityManager() {
        DefaultWebSecurityManager manager = new DefaultWebSecurityManager();
        manager.setRealm(authorizingRealm());
        manager.setSessionManager(sessionManager());
        return manager;
    }

    /**
     * 与spring集成的时候需要在web.xml中配置这个东西
     * <pre>
     * &lt;bean id="<b>myCustomFilter</b>" class="com.class.that.implements.javax.servlet.Filter"/&gt;
     * ...
     * &lt;bean id="shiroFilter" class="org.apache.shiro.spring.web.ShiroFilterFactoryBean"&gt;
     *    ...
     *    &lt;property name="filterChainDefinitions"&gt;
     *        &lt;value&gt;
     *            /some/path/** = authc, <b>myCustomFilter</b>
     *        &lt;/value&gt;
     *    &lt;/property&gt;
     * &lt;/bean&gt;
     * </pre>
     */
    @Bean
    public ShiroFilterFactoryBean shiroFilter() {
        ShiroFilterFactoryBean bean = new ShiroFilterFactoryBean();
        bean.setSecurityManager(securityManager());
        // 注册过滤器
        Map<String, Filter> filters = bean.getFilters();
        filters.put("shiroLoginFilter", shiroLoginFilter());
        filters.put("shiroLogoutFilter", shiroLogoutFilter());
        // 给不同的路径设置不同的过滤器
        Map<String, String> filterChainMap = MapUtils.putAll(
                new HashMap<>(16),
                new String[]{
                        "/login", "shiroLoginFilter",
                        "/logout", "shiroLogoutFilter",
                        "/login/getVerifyCode", "anon",
                        "/css/**", "anon",
                        "/img/**", "anon",
                        "/javascript/**", "anon",
                        "/error/**", "anon",
                        "/**", "authc"
                });
        bean.setLoginUrl("/login");
        bean.setSuccessUrl("/");
        bean.setUnauthorizedUrl("/error/403.html");
        bean.setFilterChainDefinitionMap(filterChainMap);
        return bean;
    }

    @Bean
    public Filter shiroLogoutFilter() {
        return new ShiroLogoutFilter();
    }

    @Bean
    public Filter shiroLoginFilter() {
        ShiroLoginFilter filter = new ShiroLoginFilter();
        filter.setUsernameParam("username");
        filter.setPasswordParam("password");
        return filter;
    }

    @Bean
    public HashedCredentialsMatcher credentialsMatcher() {
        ShiroCredentialsMatcher matcher = new ShiroCredentialsMatcher();
        matcher.setHashAlgorithmName("md5");
        matcher.setHashIterations(2);
        return matcher;
    }

    /**
     * 通过aop实现对注解的支持
     */
    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor() {
        AuthorizationAttributeSourceAdvisor advisor = new AuthorizationAttributeSourceAdvisor();
        advisor.setSecurityManager(securityManager());
        return advisor;
    }

    @Bean
    public SessionIdGenerator sessionIdGenerator() {
        return new JavaUuidSessionIdGenerator();
    }

    @Bean
    public SessionDAO sessionDAO() {
        EnterpriseCacheSessionDAO sessionDAO = new EnterpriseCacheSessionDAO();
        sessionDAO.setActiveSessionsCacheName("cache-name");
        sessionDAO.setSessionIdGenerator(sessionIdGenerator());
        return sessionDAO;
    }

    @Bean
    public SimpleCookie sessionIdCookie() {
        SimpleCookie simpleCookie = new SimpleCookie("sCookie");
        simpleCookie.setHttpOnly(true);
        simpleCookie.setPath("/");
        simpleCookie.setMaxAge(-1); // 关闭浏览器后失效
        return simpleCookie;
    }

}
