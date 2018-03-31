package cn.yichao.security.browser;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.social.connect.Connection;
import org.springframework.social.connect.web.ProviderSignInUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.ServletWebRequest;

import cn.yichao.security.browser.support.SocialUserInfo;
import cn.yichao.security.core.constant.ProjectConstant;
import cn.yichao.security.core.properties.SecurityPeoperties;
import cn.yichao.security.core.support.SimpleResponse;
import lombok.extern.slf4j.Slf4j; 

@RestController
@Slf4j
public class BrowseSecurityControllor {

	private RequestCache requestCache = new HttpSessionRequestCache();
	
	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
	
	@Autowired
	private SecurityPeoperties securityPeoperties;
	@Autowired
	private ProviderSignInUtils providerSignInUtils;
	
	/**
	 * 当需要身份认证时,跳转到当前方法
	 * @param httpServletResponse
	 * @param httpServletRequest
	 * @return
	 * @throws IOException 
	 */
	@RequestMapping(ProjectConstant.LOGIN_JUMP_CONTROLLER)
	@ResponseStatus(code = HttpStatus.UNAUTHORIZED)
	public SimpleResponse requireAuthentication(HttpServletResponse httpServletResponse,HttpServletRequest httpServletRequest) throws IOException {
		//拿到引发跳转的请求
		SavedRequest request = requestCache.getRequest(httpServletRequest, httpServletResponse);
		log.info("引发跳转的请求为:"  + request.getRedirectUrl() );
		if(request != null) {
			String tagUrl = request.getRedirectUrl();
			if(StringUtils.endsWithIgnoreCase(tagUrl, ".html")) {
				redirectStrategy.sendRedirect(httpServletRequest, httpServletResponse, securityPeoperties.getBrowser().getLoginPage());
			}
		}
		return new SimpleResponse("需要权限认证，请引导用户到登陆界面");
	}
	/**
	 * 获取社交用户
	 * @return
	 */
	@GetMapping("/social/user")
	public SocialUserInfo getSocialUserInfo(HttpServletRequest request) {
		SocialUserInfo socialUserInfo = new SocialUserInfo();
		Connection<?> connection = providerSignInUtils.getConnectionFromSession(new ServletWebRequest(request));
		socialUserInfo.setProviderId(connection.getKey().getProviderId());
		socialUserInfo.setProviderUserId(connection.getKey().getProviderUserId());
		socialUserInfo.setNikeName(connection.getDisplayName());
		socialUserInfo.setHeadUrl(connection.getImageUrl());
		return socialUserInfo;
	}
	@GetMapping(ProjectConstant.SESSION_INVALID)
	@ResponseStatus(code = HttpStatus.UNAUTHORIZED)
	public SimpleResponse sessionInvalid() {
		String message = "session失效";
		return new SimpleResponse(message);
	}
}
