package com.hzdaba.config.shiro;

import org.apache.shiro.authc.UsernamePasswordToken;

public class MyUsernamePasswordToken extends UsernamePasswordToken {
    /**
     * 登录类型
     */

    public MyUsernamePasswordToken(String username, String password, boolean rememberMe, String loginType){
        super(username, password, rememberMe);
        this.setLoginType(loginType);
    }

    private String LoginType;

    public String getLoginType() {
        return LoginType;
    }

    public void setLoginType(String loginType) {
        LoginType = loginType;
    }
}
