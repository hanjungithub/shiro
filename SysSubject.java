package com.hzdaba.config.shiro;

import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;

public interface SysSubject extends Subject {

    Session getSession(String loginType);

}
