package cn.yichao.security.browser;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import com.fasterxml.jackson.databind.ObjectMapper;

import cn.yichao.security.core.constant.ProjectConstant;
import cn.yichao.security.core.properties.SecurityPeoperties;
import cn.yichao.security.core.support.SimpleResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class YichaoLogoutSuccessHandler implements LogoutSuccessHandler {

	private SecurityPeoperties securityPeoperties;
	
	public static final ObjectMapper MAPPER = new ObjectMapper();
	
	public  YichaoLogoutSuccessHandler(SecurityPeoperties securityPeoperties) {
		this.securityPeoperties = securityPeoperties;
	}
	
	@Override
	public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
			throws IOException, ServletException {
		log.info("退出成功");
		String signOutUrl = securityPeoperties.getBrowser().getSignOutHtml();
		//判断是否配置退出Url
		if(StringUtils.isBlank(signOutUrl)) {
			response.setContentType(ProjectConstant.CONTENTTYPE_JSON);
			response.getWriter().write(MAPPER.writeValueAsString(new SimpleResponse("退出成功")));
		}else {
			response.sendRedirect(signOutUrl);
		}
		
	}

}
