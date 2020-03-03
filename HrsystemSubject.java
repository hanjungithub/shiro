package com.hzdaba.config.shiro;

import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.SessionContext;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.web.subject.support.WebDelegatingSubject;
import org.apache.shiro.mgt.SecurityManager;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

public class HrsystemSubject extends WebDelegatingSubject implements SysSubject {
    public HrsystemSubject(PrincipalCollection principals, boolean authenticated,
                           String host, Session session, boolean sessionEnabled,
                           ServletRequest request, ServletResponse response,
                           SecurityManager securityManager) {
        super(principals, authenticated, host, session, sessionEnabled, request, response, securityManager);
    }

    public Session getSession(String type) {
        SessionContext sessionContext = createSessionContext();
        sessionContext.put("loginType", type);
        Session session = this.securityManager.start(sessionContext);
        super.session = decorate(session);
        return super.session;
    }
}
