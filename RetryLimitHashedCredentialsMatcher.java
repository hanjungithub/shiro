package com.hzdaba.config.shiro;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.ExcessiveAttemptsException;
import org.apache.shiro.authc.SaltedAuthenticationInfo;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.crypto.hash.DefaultHashService;
import org.apache.shiro.crypto.hash.HashRequest;
import org.apache.shiro.util.ByteSource;
import org.springframework.util.StringUtils;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Created by DELL on 2017/12/13.
 */
public class RetryLimitHashedCredentialsMatcher extends HashedCredentialsMatcher {

    private Cache<String, AtomicInteger> passwordRetryCache;

    private CacheManager cacheManager;

    private String passwordRetryCacheName;

    public RetryLimitHashedCredentialsMatcher(CacheManager cacheManager) {
        this.cacheManager=cacheManager;
    }

    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        if(StringUtils.isEmpty(passwordRetryCacheName)){
            passwordRetryCacheName="passwordRetryCache";
        }
        passwordRetryCache=cacheManager.getCache(passwordRetryCacheName);

        String username = (String)token.getPrincipal();
        String cacheKey=passwordRetryCacheName+":"+username;
        //retry count + 1
        Object obj=passwordRetryCache.get(cacheKey);
        AtomicInteger retryCount = null;
        if(obj == null) {
            retryCount = new AtomicInteger(0);
            passwordRetryCache.put(cacheKey, retryCount);
        }else{
            retryCount = (AtomicInteger) obj;

        }
        if(retryCount.incrementAndGet() > 3) {
            //if retry count > 5 throw
            throw new ExcessiveAttemptsException();
        }

        boolean matches=matches(token,info);
//        boolean matches = super.doCredentialsMatch(token, info);
        if(matches) {
            //clear retry count
            passwordRetryCache.remove(username);
        }
        return matches;
    }

    public void setPasswordRetryCacheName(String passwordRetryCacheName) {
        this.passwordRetryCacheName = passwordRetryCacheName;
    }

    /**
     * 验证密码是否匹配
     * @param token
     * @param info
     * @return
     */
    public boolean matches(AuthenticationToken token, AuthenticationInfo info){
        String password= new String((char[]) token.getCredentials());
        ByteSource saltByteSource = ((SaltedAuthenticationInfo)info).getCredentialsSalt();

        DefaultHashService hashService=new DefaultHashService();
        hashService.setHashAlgorithmName(getHashAlgorithmName());
        hashService.setPrivateSalt(saltByteSource);
        hashService.setHashIterations(getHashIterations());

        HashRequest request=new HashRequest.Builder()
                .setAlgorithmName(getHashAlgorithmName()).setSource(ByteSource.Util.bytes(password))
                .setSalt(ByteSource.Util.bytes(saltByteSource)).setIterations(getHashIterations()).build();

        ByteSource tokenHashedCredentials = ByteSource.Util.bytes(hashService.computeHash(request).getBytes());

        Object accountCredentials = this.getCredentials(info);
        return this.equals(tokenHashedCredentials, accountCredentials);
    }
}
