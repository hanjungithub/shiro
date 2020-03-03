package com.hzdaba.config.shiro;

import com.hzdaba.service.AuthorityService;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.permission.RolePermissionResolver;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.Serializable;
import java.util.Collection;

/**
 * Created by DELL on 2017/12/13.
 */
public class MyRolePermissionResolver implements RolePermissionResolver,Serializable {

    private static final long serialVersionUID = -6071591919458732103L;

    @Autowired
    private AuthorityService authorityService;

    public MyRolePermissionResolver(){}

    public MyRolePermissionResolver(AuthorityService authorityService){
        this.authorityService=authorityService;
    }

    @Override
    public Collection<Permission> resolvePermissionsInRole(String s) {
        return authorityService.findByRole(s);
    }

    public void setUserService(AuthorityService authorityService) {
        this.authorityService = authorityService;
    }
}
