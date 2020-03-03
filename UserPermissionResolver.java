package com.hzdaba.config.shiro;

import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.permission.PermissionResolver;

/**
 * Created by DELL on 2017/12/13.
 */
public class UserPermissionResolver implements PermissionResolver {

    @Override
    public Permission resolvePermission(String s) {
        return new UserPermission(s);
    }
}
