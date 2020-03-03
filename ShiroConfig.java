package com.hzdaba.config.shiro;

import com.hzdaba.service.AuthorityService;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authc.pam.AtLeastOneSuccessfulStrategy;
import org.apache.shiro.authc.pam.ModularRealmAuthenticator;
import org.apache.shiro.authz.ModularRealmAuthorizer;
import org.apache.shiro.authz.permission.RolePermissionResolver;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.mgt.SessionFactory;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.servlet.Cookie;
import org.crazycake.shiro.RedisCacheManager;
import org.crazycake.shiro.RedisManager;
import org.crazycake.shiro.RedisSessionDAO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;

import javax.servlet.Filter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.util.StringUtils.isEmpty;

/**
 * Created by DELL on 2017/12/13.
 */
@Configuration
public class ShiroConfig {

    @Value("${spring.redis.host}")
    private String host;

    @Value("${spring.redis.port}")
    private int port;

    @Value("${spring.redis.password}")
    private String password;

    @Value("${shiro.redisCacheExpire:1800}")
    private int redisCacheExpire;

    @Value("${shiro.filterChainDefinitions}")
    private String filterChainDefinitions;

    @Autowired
    private AuthorityService authorityService;


    /**
     * 配置shiro redisManager
     * 使用的是shiro-redis开源插件
     *
     * @return
     */
    public RedisManager redisManager() {
        RedisManager redisManager = new RedisManager();
        redisManager.setHost(host);
        redisManager.setPort(port);
        if (org.apache.commons.lang3.StringUtils.isNotEmpty(password)) {
            redisManager.setPassword(password);
        }
        redisManager.setExpire(redisCacheExpire);
//        redisManager.setTimeout(2000);
        return redisManager;
    }

    /**
     * cacheManager 缓存 redis实现
     * 使用的是shiro-redis开源插件
     *
     * @return
     */
    public RedisCacheManager cacheManager() {
        RedisCacheManager redisCacheManager = new RedisCacheManager();
        redisCacheManager.setRedisManager(redisManager());
        return redisCacheManager;
    }

    /**
     * RedisSessionDAO shiro sessionDao层的实现 通过redis
     * 使用的是shiro-redis开源插件
     */
    public RedisSessionDAO redisSessionDAO() {
        RedisSessionDAO redisSessionDAO = new RedisSessionDAO();
        redisSessionDAO.setRedisManager(redisManager());
        //重新实现sessionId
        redisSessionDAO.setSessionIdGenerator(new MySessionIdGenerator());
        return redisSessionDAO;
    }

    /**
     * shiro session的管理
     */
    public SessionManager sessionManager() {
        MySessionManager mySessionManager = new MySessionManager();
        mySessionManager.setSessionFactory(hrsystemSessionFactory());
        mySessionManager.setSessionDAO(redisSessionDAO());
        //不同项目同域名下cookie对sessionId的处理
        Cookie cookie = mySessionManager.getSessionIdCookie();
        cookie.setName("sid");
        mySessionManager.setSessionIdCookie(cookie);
        return mySessionManager;
    }
    @Bean
    public  HrsystemSessionFactory hrsystemSessionFactory(){
        return new HrsystemSessionFactory();
    }

    /**
     * 凭证匹配器
     *
     * @return
     */
    public CredentialsMatcher credentialsMatcher() {
        RetryLimitHashedCredentialsMatcher credentialsMatcher = new RetryLimitHashedCredentialsMatcher(cacheManager());
        credentialsMatcher.setHashAlgorithmName("md5");//加密算法名称
        credentialsMatcher.setHashIterations(2);
        credentialsMatcher.setStoredCredentialsHexEncoded(true);
        return credentialsMatcher;
    }

    /**
     * Realm实现
     *
     * @return
     */
    @Bean
    public AuthorizingRealm userRealm() {
        UserRealm userRealm = new UserRealm();
        userRealm.setName("user");
        userRealm.setCredentialsMatcher(credentialsMatcher());
        //用户信息不缓存
        userRealm.setAuthenticationCachingEnabled(false);
        userRealm.setAuthorizationCachingEnabled(true);
        return userRealm;
    }

    /**
     * EmpRealm实现
     *
     * @return
     */
    @Bean
    public AuthorizingRealm EmployeeRealm() {
        EmployeeRealm employeeRealm = new EmployeeRealm();
        employeeRealm.setName("emp");
        employeeRealm.setCredentialsMatcher(credentialsMatcher());
        //用户信息不缓存
        employeeRealm.setAuthenticationCachingEnabled(false);
        employeeRealm.setAuthorizationCachingEnabled(true);
        return employeeRealm;
    }

    /**
     * 安全管理器
     *
     * @return
     */
    @Bean
    public SecurityManager securityManager() {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();

        securityManager.setSubjectFactory(hrsystemSubjectFactory());

        List<Realm> realms = new ArrayList<>();
        securityManager.setAuthenticator(modularRealmAuthenticator());
        //添加多个Realm
        realms.add(userRealm());
        realms.add(EmployeeRealm());
        securityManager.setRealms(realms);
        securityManager.setSessionManager(sessionManager());
        securityManager.setCacheManager(cacheManager());


        MyModularRealmAuthorizer authorizer = new MyModularRealmAuthorizer();
        authorizer.setRealms(securityManager.getRealms());
        authorizer.setPermissionResolver(new UserPermissionResolver());
        authorizer.setRolePermissionResolver(rolePermissionResolver());

        securityManager.setAuthorizer(authorizer);

        securityManager.setRememberMeManager(rememberMeManager());

        return securityManager;
    }

    @Bean
    public HrsystemSubjectFactory hrsystemSubjectFactory(){
        return new HrsystemSubjectFactory();
    }

    /**
     * 系统自带的Realm管理，主要针对多realm
     * */
    @Bean
    public ModularRealmAuthenticator modularRealmAuthenticator(){
        //自己重写的ModularRealmAuthenticator
        MyModularRealmAuthenticator modularRealmAuthenticator = new MyModularRealmAuthenticator();
        modularRealmAuthenticator.setAuthenticationStrategy(new AtLeastOneSuccessfulStrategy());
        return modularRealmAuthenticator;
    }


    @Bean
    public RolePermissionResolver rolePermissionResolver() {
        return new MyRolePermissionResolver();
    }

    @Bean
    public ShiroFilterFactoryBean shiroFilter(SecurityManager securityManager) {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        shiroFilterFactoryBean.setSecurityManager(securityManager);

        Map<String, Filter> filters = shiroFilterFactoryBean.getFilters();
        StaticUrlFilter staticUrlFilter = new StaticUrlFilter();
        filters.put("staticUrl", staticUrlFilter);
        SecurityFilter securityFilter = new SecurityFilter();
        filters.put("security", securityFilter);
        AuthorityFilter authorityFilter = new AuthorityFilter();
        authorityFilter.setActionService(authorityService);
        filters.put("auth", authorityFilter);
        shiroFilterFactoryBean.setFilters(filters);
        //拦截器.
        Map<String, String> filterChainDefinitionMap = new LinkedHashMap<String, String>();
        // 配置不会被拦截的链接 顺序判断
        //拦截器url配置格式为：/**=user，等号前面为路径，后面为名称，多个拦截器用','分割，多个配置之间用';'分割
        if (!StringUtils.isEmpty(filterChainDefinitions)) {
            String[] array = StringUtils.delimitedListToStringArray(filterChainDefinitions, ";");
            for (String str : array) {
                if(isEmpty(str)){
                    continue;
                }
                String[] urlArray = str.split("=");

                filterChainDefinitionMap.put(urlArray[0].trim(), urlArray[1].trim());
                /*String[] filterArray = urlArray[1].split(",");
                for (String s : filterArray) {
                    filterChainDefinitionMap.put(urlArray[0].trim(), s.trim());
                }*/
            }
        }
        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
//        shiroFilterFactoryBean.setFilterChainDefinitions(filterChainDefinitions);
        // 如果不设置默认会自动寻找Web工程根目录下的"/login.jsp"页面
        shiroFilterFactoryBean.setLoginUrl("/login");
        // 登录成功后要跳转的链接
        shiroFilterFactoryBean.setSuccessUrl("/");
        shiroFilterFactoryBean.setUnauthorizedUrl("/401");

        return shiroFilterFactoryBean;
    }


    public CookieRememberMeManager rememberMeManager() {
        CookieRememberMeManager rememberMeManager = new CookieRememberMeManager();
        rememberMeManager.getCookie().setMaxAge(2592000);//有效期30天
        rememberMeManager.setCipherKey(Base64.decode("4AvVhmFLUs0KTA3Kprsdag=="));
        return rememberMeManager;
    }

}
