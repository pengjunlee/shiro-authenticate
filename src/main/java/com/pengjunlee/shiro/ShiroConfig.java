package com.pengjunlee.shiro;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authc.pam.AtLeastOneSuccessfulStrategy;
import org.apache.shiro.authc.pam.AuthenticationStrategy;
import org.apache.shiro.authc.pam.ModularRealmAuthenticator;
import org.apache.shiro.cache.ehcache.EhCacheManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import net.sf.ehcache.CacheManager;

@Configuration
public class ShiroConfig {

	/**
	 * 交由 Spring 来自动地管理 Shiro-Bean 的生命周期
	 */
	@Bean
	public static LifecycleBeanPostProcessor getLifecycleBeanPostProcessor() {
		return new LifecycleBeanPostProcessor();
	}

	/**
	 * 配置访问资源需要的权限
	 */
	@Bean
	ShiroFilterFactoryBean shiroFilterFactoryBean(SecurityManager securityManager) {
		ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
		shiroFilterFactoryBean.setSecurityManager(securityManager);
		shiroFilterFactoryBean.setLoginUrl("/login");
		shiroFilterFactoryBean.setSuccessUrl("/authorized");
		shiroFilterFactoryBean.setUnauthorizedUrl("/unauthorized");
		LinkedHashMap<String, String> filterChainDefinitionMap = new LinkedHashMap<String, String>();
		filterChainDefinitionMap.put("/login", "anon"); // 可匿名访问
		filterChainDefinitionMap.put("/logout", "logout"); // 退出登录
		filterChainDefinitionMap.put("/**", "authc"); // 需登录才能访问
		shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
		return shiroFilterFactoryBean;
	}

	/**
	 * 配置 SecurityManager，通常需要配置以下属性： 1.CacheManager 2.Realm 3.SessionManager
	 */
	@Bean
	public SecurityManager securityManager() {
		DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();

		// 1.CacheManager
		securityManager.setCacheManager(ehCacheManager());

		// 设置 Authenticator
		securityManager.setAuthenticator(authenticator());

		// 2.Realm
		// securityManager.setRealm(loginRealm());
		List<Realm> realms = new ArrayList<Realm>(16);
		realms.add(loginRealm());
		realms.add(userRealm());
		securityManager.setRealms(realms);

		// 3.SessionManager
		securityManager.setSessionManager(sessionManager());
		return securityManager;
	}

	/**
	 * 配置 ModularRealmAuthenticator
	 */
	@Bean
	public ModularRealmAuthenticator authenticator() {
		ModularRealmAuthenticator authenticator = new ModularRealmAuthenticator();
		// 设置多 Realm的认证策略，默认 AtLeastOneSuccessfulStrategy
		AuthenticationStrategy strategy = new AtLeastOneSuccessfulStrategy();
		authenticator.setAuthenticationStrategy(strategy);
		return authenticator;
	}

	/**
	 * EhCacheManager缓存配置，默认使用 classpath:/ehcache.xml
	 */
	@Bean("cacheManager")
	public EhCacheManager ehCacheManager() {
		EhCacheManager em = new EhCacheManager();
		em.setCacheManager(cacheManager());
		return em;
	}

	@Bean("cacheManager2")
	CacheManager cacheManager() {
		return CacheManager.create();
	}

	/**
	 * Realm1 配置，需实现 Realm 接口
	 */
	@Bean
	LoginRealm loginRealm() {
		LoginRealm loginRealm = new LoginRealm();
		// 设置加密算法
		HashedCredentialsMatcher credentialsMatcher = new HashedCredentialsMatcher("SHA-1");
		// 设置加密次数
		credentialsMatcher.setHashIterations(16);
		loginRealm.setCredentialsMatcher(credentialsMatcher);
		return loginRealm;
	}

	/**
	 * Realm2 配置，需实现 Realm 接口
	 */
	@Bean
	UserRealm userRealm() {
		UserRealm userRealm = new UserRealm();
		// 设置加密算法
		HashedCredentialsMatcher credentialsMatcher = new HashedCredentialsMatcher("MD5");
		// 设置加密次数
		credentialsMatcher.setHashIterations(16);
		userRealm.setCredentialsMatcher(credentialsMatcher);
		return userRealm;
	}

	/**
	 * SessionManager配置
	 */
	@Bean
	public DefaultWebSessionManager sessionManager() {
		DefaultWebSessionManager sessionManager = new DefaultWebSessionManager();
		sessionManager.setGlobalSessionTimeout(1800 * 1000);
		sessionManager.setDeleteInvalidSessions(true);
		sessionManager.setSessionValidationSchedulerEnabled(true);
		return sessionManager;
	}

}
