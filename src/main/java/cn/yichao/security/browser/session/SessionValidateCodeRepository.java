package cn.yichao.security.browser.session;

import org.springframework.social.connect.web.HttpSessionSessionStrategy;
import org.springframework.social.connect.web.SessionStrategy;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.ServletWebRequest;
import cn.yichao.security.core.vlidate.ValidateCode;
import cn.yichao.security.core.vlidate.ValidateCodeRepository;

@Component("sessionCodeRepository")
public class SessionValidateCodeRepository implements ValidateCodeRepository {
	
	private SessionStrategy sessionStrategy = new HttpSessionSessionStrategy();	
	
	@Override
	public void save(ServletWebRequest request, ValidateCode validateCode, String validateCodeKey) {
		sessionStrategy.setAttribute(request,validateCodeKey, validateCode);
	}

	@Override
	public ValidateCode get(ServletWebRequest request,String validateCodeKey) {
		return (ValidateCode) sessionStrategy.getAttribute(request, validateCodeKey);
	}

 
 
	@Override
	public void remove(ServletWebRequest request,String validateCodeKey) {
		sessionStrategy.removeAttribute(request, validateCodeKey);

	}

}
