package com.hzdaba.config.shiro;

import com.alibaba.fastjson.JSON;

import com.hzdaba.entity.bo.Result;
import com.hzdaba.entity.model.Employee;
import com.hzdaba.entity.model.User;
import com.hzdaba.utils.EmpUtil;
import com.hzdaba.utils.UserUtil;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;

/**
 * 账号安全拦截
 */
public class SecurityFilter extends AccessControlFilter {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Override
    protected boolean isAccessAllowed(ServletRequest servletRequest, ServletResponse servletResponse, Object o) throws Exception {
        HttpServletRequest req = WebUtils.toHttp(servletRequest);
        String requestURI = req.getRequestURI();
        User user = UserUtil.getCurrentUser();
        Employee employee = EmpUtil.getCurrentUser();
        if (user == null && employee==null) {
            if (requestURI.equals("/login") ||requestURI.equals("/emp/login") ) {
                //登录或退出不拦截
                return true;
            } else {
                return false;
            }
        }
        return true;
    }

    @Override
    protected boolean onAccessDenied(ServletRequest servletRequest, ServletResponse servletResponse) throws Exception {
        servletResponse.setCharacterEncoding("UTF-8");
        PrintWriter writer = WebUtils.toHttp(servletResponse).getWriter();
        Result result = new Result();
        result.setResult(false);
        result.setMsg("账号已过期");
        result.setAction(50014); // token非法:50008 在其他地方登陆:50012 账号已过期:50014
        writer.write(JSON.toJSONString(result));
        writer.flush();
        return false;
    }

}
