package com.hzdaba.config.shiro;

import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.SessionContext;
import org.apache.shiro.session.mgt.SessionFactory;
import org.apache.shiro.session.mgt.SimpleSession;
import org.apache.shiro.web.session.mgt.WebSessionContext;

import javax.servlet.http.HttpServletRequest;

public class HrsystemSessionFactory implements SessionFactory {
    @Override
    public Session createSession(SessionContext initData) {
        Session session = null;
        if (initData != null) {
            String host = initData.getHost();
            if (host != null) {
                session = new SimpleSession(host);
            }
            WebSessionContext sessionContext = (WebSessionContext) initData;
            HttpServletRequest request = (HttpServletRequest) sessionContext.getServletRequest();
            System.out.println("--------------------------------:"+request.getAttribute("xxxx"));
            if(initData.get("loginType")!=null){
                session.setAttribute("loginType", initData.get("loginType"));
            }
        }else{
            session = new SimpleSession();
        }
        return session;
    }
}
