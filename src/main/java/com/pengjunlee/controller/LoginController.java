package com.pengjunlee.controller;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.pengjunlee.domain.UserEntity;

@Controller
public class LoginController {

	@GetMapping("/login")
	public String login() {
		return "login";
	}

	@PostMapping(value = "/login")
	public String userLogin(@RequestParam(name = "username") String userName,
			@RequestParam(name = "password") String password, ModelMap model) {

		// 获取当前用户主体
		Subject subject = SecurityUtils.getSubject();
		String msg = null;
		// 判断是否已经验证身份，即是否已经登录
		if (!subject.isAuthenticated()) {
			// 将用户名和密码封装成 UsernamePasswordToken 对象
			UsernamePasswordToken token = new UsernamePasswordToken(userName, password);
			try {
				subject.login(token);
				System.out.println("用户 [ " + userName + " ] 登录成功。");
				addUserInfo2Model(model);

			} catch (UnknownAccountException uae) { // 账号不存在
				msg = "用户名与密码不匹配，请检查后重新输入！";
			} catch (IncorrectCredentialsException ice) { // 账号与密码不匹配
				msg = "用户名与密码不匹配，请检查后重新输入！";
			} catch (LockedAccountException lae) { // 账号已被锁定
				msg = "该账户已被锁定，如需解锁请联系管理员！";
			} catch (AuthenticationException ae) { // 其他身份验证异常
				msg = "登录异常，请联系管理员！";
			}
		}

		if (subject.isAuthenticated()) {
			return "redirect:/authorized";
		} else {
			model.addAttribute("msg", msg);
			return "403";
		}

	}

	@GetMapping("/logout")
	public String logout() {
		return "redirect:/login";
	}

	@GetMapping("/unauthorized")
	public String unauthorized(ModelMap model) {
		return "403";
	}

	@GetMapping("/authorized")
	public String authorized(ModelMap model) {
		addUserInfo2Model(model);
		return "success";
	}

	// 将用户信息添加到 model
	private void addUserInfo2Model(ModelMap model) {
		Subject subject = SecurityUtils.getSubject();
		UserEntity currentUser = (UserEntity) subject.getPrincipal();
		model.addAttribute("user", currentUser);
	}
}
