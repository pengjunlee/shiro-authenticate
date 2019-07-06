package com.pengjunlee.shiro;

import java.util.HashMap;
import java.util.Map;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.util.ByteSource;

import com.pengjunlee.domain.UserEntity;

/**
 * 只开启身份验证，继承 AuthenticatingRealm 并实现 doGetAuthenticationInfo() 方法即可
 */
public class LoginRealm extends AuthenticatingRealm {

	private static Map<String, UserEntity> users = new HashMap<String, UserEntity>(16);

	static {
		UserEntity user1 = new UserEntity(1L, "graython", "dd524c4c66076d1fa07e1fa1c94a91233772d132", "灰先生", false);
		UserEntity user2 = new UserEntity(2L, "plum", "cce369436bbb9f0325689a3a6d5d6b9b8a3f39a0", "李先生", false);
		UserEntity user3 = new UserEntity(3L, "nightking", "4d49589af1a6d72c1f89a0a3fa47050ebb639246", "夜王", false);
		UserEntity user4 = new UserEntity(4L, "guomeimei", "ce0777770937547f8a43193eb853ce609b7e2307", "郭妹妹", true);

		users.put("graython", user1);
		users.put("plum", user2);
		users.put("nightking", user3);
		users.put("guomeimei", user4);
	}

	/**
	 * 查询数据库，将获取到的用户安全数据封装返回
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		// 从 AuthenticationToken 中获取当前用户
		String username = (String) token.getPrincipal();
		// 查询数据库获取用户信息，此处使用 Map 来模拟数据库
		UserEntity user = users.get(username);

		// 用户不存在
		if (user == null) {
			throw new UnknownAccountException("用户不存在！");
		}

		// 用户被锁定
		if (user.getLocked()) {
			throw new LockedAccountException("该用户已被锁定,暂时无法登录！");
		}

		/**
		 * 将获取到的用户数据封装成 AuthenticationInfo 对象返回，此处封装为 SimpleAuthenticationInfo
		 * 对象。 
		 * 参数1. 认证的实体信息，可以是从数据库中获取到的用户实体类对象或者用户名 
		 * 参数2. 查询获取到的登录密码 
		 * 参数3. 当前 Realm 对象的名称，直接调用父类的 getName() 方法即可
		 */
		// SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(user, user.getPassword(), getName());
		
		// 使用用户名作为盐值
		ByteSource credentialsSalt = ByteSource.Util.bytes(username);

		/**
		 * 将获取到的用户数据封装成 AuthenticationInfo 对象返回，此处封装为 SimpleAuthenticationInfo 对象。 
		 * 参数1. 认证的实体信息，可以是从数据库中获取到的用户实体类对象或者用户名 
		 * 参数2. 查询获取到的登录密码
		 * 参数3. 盐值
		 * 参数4. 当前 Realm 对象的名称，直接调用父类的 getName() 方法即可
		 */
		SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(user, user.getPassword(), credentialsSalt,
				getName());
		return info;
	}

	public static void main(String[] args) {
		/**
		 * 可以使用如下方法获取某一字符串加密后的密文
		 * algorithmName 算法类型 例：SHA-1
		 * source 要加密的字符串
		 * salt 盐值
		 * hashIterations 加密次数
		 */
		new SimpleHash("SHA-1", "123456", "guomeimei", 16);
	}

}
