package com.hzdaba.config.shiro;

import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.eis.JavaUuidSessionIdGenerator;
import org.apache.shiro.session.mgt.eis.SessionIdGenerator;

import java.io.Serializable;
import java.util.UUID;

public class MySessionIdGenerator implements SessionIdGenerator {
    @Override
    public Serializable generateId(Session session) {
        if(session.getAttribute("loginType")!=null){
            return session.getAttribute("loginType").toString()+"_"+UUID.randomUUID().toString();
        }
        return UUID.randomUUID().toString();
    }
}
