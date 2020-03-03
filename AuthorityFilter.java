package com.hzdaba.config.shiro;

import com.alibaba.fastjson.JSON;
import com.hzdaba.entity.bo.Result;
import com.hzdaba.service.AuthorityService;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authz.AuthorizationFilter;
import org.apache.shiro.web.servlet.ShiroHttpServletResponse;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * 自定义shiro过滤器，用来做动态权限验证
 * Created by DELL on 2017/12/16.
 */
public class AuthorityFilter extends AuthorizationFilter {

    private final Logger logger= LoggerFactory.getLogger(this.getClass());

    private AuthorityService authorityService;

    @Override
    protected boolean isAccessAllowed(ServletRequest servletRequest, ServletResponse servletResponse, Object o) throws Exception {
        if(isLoginRequest(servletRequest,servletResponse)){
            return true;
        }else{
            Subject subject = this.getSubject(servletRequest, servletResponse);
            String requestUri=getPathWithinApplication(servletRequest);
            //判断是否登录或者401
            if(subject.getPrincipal() == null||isUnauthorizedRequest(requestUri)){
                return false;
            }
            //判断当前url是否需要验证权限
            if(!authorityService.findAction(requestUri)){
                return true;
            }

            String path = getPathWithinApplication(servletRequest);
            try {
                subject.checkPermission(path);
            } catch (AuthorizationException e) {
                if(logger.isErrorEnabled()){
                    logger.error(e.getMessage(),e);
                }
                return false;
            }
        }
        return true;
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        response.setCharacterEncoding("UTF-8");
            PrintWriter writer = WebUtils.toHttp(response).getWriter();
            Result result = new Result();
            result.setResult(false);
            result.setMsg("没有权限");
            result.setAction(50014); // token非法:50008 在其他地方登陆:50012 账号已过期:50014
            writer.write(JSON.toJSONString(result));
            writer.flush();
            return false;
    }

    private boolean isUnauthorizedRequest(String requestUri){
        if(getUnauthorizedUrl()!=null&&getUnauthorizedUrl().equals(requestUri)){
            return true;
        }
        return false;
    }


    public void setActionService(AuthorityService authorityService) {
        this.authorityService = authorityService;
    }

}
