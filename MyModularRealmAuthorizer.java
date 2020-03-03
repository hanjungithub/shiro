package com.hzdaba.config.shiro;

import com.hzdaba.entity.model.Employee;
import com.hzdaba.entity.model.User;
import org.apache.shiro.authz.Authorizer;
import org.apache.shiro.authz.ModularRealmAuthorizer;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.PrincipalCollection;

public class MyModularRealmAuthorizer extends ModularRealmAuthorizer {

    @Override
    public boolean isPermitted(PrincipalCollection principals, String permission) {
        assertRealmsConfigured();
        Object primaryPrincipal = principals.getPrimaryPrincipal();

        for (Realm realm : getRealms()) {
            if (!(realm instanceof Authorizer)) continue;
            if (User.class.getName().equals(primaryPrincipal.getClass().getName())) {
                if (realm instanceof UserRealm) {
                    return ((UserRealm) realm).isPermitted(principals, permission);
                }
            }
            if (Employee.class.getName().equals(primaryPrincipal.getClass().getName())) {
                if (realm instanceof EmployeeRealm) {
                    return ((EmployeeRealm) realm).isPermitted(principals, permission);
                }
            }

        }
        return false;
    }
}
