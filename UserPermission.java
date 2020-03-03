package com.hzdaba.config.shiro;

import org.apache.shiro.authz.Permission;

import java.io.Serializable;

/**
 * Created by DELL on 2017/12/13.
 */
public class UserPermission implements Permission,Serializable {

    private static final long serialVersionUID = -883177586102659328L;

    private String actionUrl;

    public UserPermission(String actionUrl){
        this.actionUrl=actionUrl;
    }

    @Override
    public boolean implies(Permission permission) {
        if(!(permission instanceof UserPermission)){
            return false;
        }
        UserPermission other= (UserPermission) permission;
        if(!actionUrl.equals(other.actionUrl)){
            return false;
        }
        return true;
    }
}
