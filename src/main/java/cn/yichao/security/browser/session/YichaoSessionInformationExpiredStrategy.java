package cn.yichao.security.browser.session;

import java.io.IOException;

import javax.servlet.ServletException;

import org.springframework.security.web.session.SessionInformationExpiredEvent;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

import cn.yichao.security.core.constant.ProjectConstant;

public class YichaoSessionInformationExpiredStrategy implements SessionInformationExpiredStrategy {

	@Override
	public void onExpiredSessionDetected(SessionInformationExpiredEvent event) throws IOException, ServletException {
		event.getResponse().setContentType(ProjectConstant.CONTENTTYPE_JSON);
		event.getResponse().getWriter().write("并发登陆");
	}

}
