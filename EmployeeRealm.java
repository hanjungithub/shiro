package com.hzdaba.config.shiro;

import com.alibaba.fastjson.JSON;


import com.hzdaba.dic.EmpConstants;
import com.hzdaba.entity.model.Employee;
import com.hzdaba.excepitions.LoginRepeatException;
import com.hzdaba.service.EmpAuthorityService;
import com.hzdaba.service.RedisService;
import com.hzdaba.utils.EmpUtil;
import com.hzdaba.utils.LogUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.support.DefaultSubjectContext;
import org.apache.shiro.util.ByteSource;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.UnsupportedEncodingException;
import java.util.Collection;

/**
 * Created by DELL on 2017/12/13.
 */
public class EmployeeRealm extends AuthorizingRealm {

    private Logger logger = LoggerFactory.getLogger(this.getClass());

    @Autowired
    private EmpAuthorityService empAthorityService;

    @Autowired
    private RedisService redisService;

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        String account = ((Employee) principalCollection.getPrimaryPrincipal()).getAccount();
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        authorizationInfo.setRoles(empAthorityService.findRoles(account));

        return authorizationInfo;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        String account = (String) authenticationToken.getPrincipal();
        Employee employee = empAthorityService.findByAccount(account);

        if (employee == null) {
            throw new UnknownAccountException();//没找到帐号
        }

        if (Boolean.TRUE.equals(employee.getLocked())) {
            throw new LockedAccountException(); //帐号锁定
        }

        //处理session
        DefaultWebSecurityManager securityManager = (DefaultWebSecurityManager) SecurityUtils.getSecurityManager();
        DefaultWebSessionManager sessionManager = (DefaultWebSessionManager) securityManager.getSessionManager();
        Collection<Session> sessions = sessionManager.getSessionDAO().getActiveSessions();//获取当前已登录的用户session列表

        for (Session session : sessions) {
            String str = (String) session.getAttribute(EmpConstants.CURRENT_USER);
            //说明重复登录
            if (str != null && account.equals(String.valueOf(session.getAttribute(DefaultSubjectContext.PRINCIPALS_SESSION_KEY)))) {
                //判断是否是坐席
                if (StringUtils.isNotEmpty(str)
                        && JSON.parseObject(str).getInteger("roleId") == 2) {
                    String key = EmpConstants.SEAT_INFO_PREFIX + ":" + employee.getUserId() + ":" + employee.getSkillGroupId() + ":" + employee.getId();
                    String redisEmpJSON = null;
                    try {
                        redisEmpJSON = redisService.get(key);
                    } catch (UnsupportedEncodingException e) {
                        LogUtils.error(logger,e.getMessage());
                    }
                    //判断坐席是否在线
                    if (StringUtils.isNoneBlank(redisEmpJSON) && JSON.parseObject(redisEmpJSON).getInteger("notworkingStatus") != 2) {
                        throw new LoginRepeatException();
                    }
                }
            }
        }
        //清空账号上一个记录token、session
        EmpUtil.removeSession(account);

        //salt=username+salt
        MyByteSource saltByteSource = new MyByteSource(ByteSource.Util.bytes(employee.getAccount()
                + employee.getSalt()).getBytes());

        //交给AuthenticatingRealm使用CredentialsMatcher进行密码匹配，如果觉得人家的不好可以自定义实现
        SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(
                employee, //账号
                employee.getPassword(), //密码
                saltByteSource,
                getName()  //realm name
        );
        return authenticationInfo;
    }

    @Override
    public void clearCachedAuthorizationInfo(PrincipalCollection principals) {
        super.clearCachedAuthorizationInfo(principals);
    }

    @Override
    public void clearCachedAuthenticationInfo(PrincipalCollection principals) {
        super.clearCachedAuthenticationInfo(principals);
    }

    @Override
    public void clearCache(PrincipalCollection principals) {
        super.clearCache(principals);
    }

    public void clearAllCachedAuthorizationInfo() {
        getAuthorizationCache().clear();
    }

    public void clearAllCachedAuthenticationInfo() {
        getAuthenticationCache().clear();
    }

    public void clearCachedAuthorizationInfo(String username) {
        Cache cache = this.getAuthenticationCache();
        if (cache != null) {
            cache.remove(username);
        }
    }
}
