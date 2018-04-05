package cn.yichao.security.browser;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean; 
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.social.security.SpringSocialConfigurer;
import org.springframework.stereotype.Component;

import cn.yichao.security.browser.session.YichaoSessionInformationExpiredStrategy;
import cn.yichao.security.core.authentication.mobile.SmsAuthentioncationSecurityConfig;
import cn.yichao.security.core.authorize.AuthorizeConfigManager;
import cn.yichao.security.core.constant.ProjectConstant;
import cn.yichao.security.core.properties.SecurityPeoperties;
import cn.yichao.security.core.vlidate.ValidateCodeRepository;
import cn.yichao.security.core.vlidate.core.ValidateCodeFiler;
import cn.yichao.security.core.vlidate.core.sms.SmsValidateCodeFiler;
@Component
public class BrowserSecurityConfig extends WebSecurityConfigurerAdapter {

	
	@Autowired
	private SecurityPeoperties securityPeoperties;
	@Autowired
	private AuthenticationSuccessHandler yichaoAuthenticationSuccessHandler;
	@Autowired
	private AuthenticationFailureHandler yichaoAuthenticationFailuHandler;
	@Autowired
	private DataSource dataSource;
	@Autowired
	private UserDetailsService myUserDetailsServcie;
	@Autowired
	private SmsAuthentioncationSecurityConfig smsAuthentioncationSecurityConfig;
	@Autowired
	private SpringSocialConfigurer securitySocialConfigurer;
	@Autowired
	private SessionInformationExpiredStrategy sessionInformationExpiredStrategy;
	@Autowired
	private LogoutSuccessHandler logoutSuccessHandler;
	@Autowired
	private ValidateCodeRepository sessionCodeRepository;
	@Autowired
	private  AuthorizeConfigManager authorizeConfigManager;
	

	/**
	 * 如果不存在该Bean 走默认配置,
	 * 正式项目可以修改该配置项
	 * @return
	 */
	@Bean
	@ConditionalOnMissingBean(name = "sessionInformationExpiredStrategy")
	public SessionInformationExpiredStrategy sessionInformationExpiredStrategy(){
		return new YichaoSessionInformationExpiredStrategy();
	}
	@Bean
	@ConditionalOnMissingBean(name = "logoutSuccessHandler")
	public LogoutSuccessHandler logoutSuccessHandler(){
		return new YichaoLogoutSuccessHandler(securityPeoperties);		
	}
	
	
	
	@Bean
	private PersistentTokenRepository persistentTokenRepository() {
		JdbcTokenRepositoryImpl jdbcTokenRepositoryImpl = new JdbcTokenRepositoryImpl();
		jdbcTokenRepositoryImpl.setDataSource(dataSource);
		//启动时创建表
		jdbcTokenRepositoryImpl.setCreateTableOnStartup(false);
		return jdbcTokenRepositoryImpl;
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		//图片验证码
		 ValidateCodeFiler validateCodeFiler = new ValidateCodeFiler(sessionCodeRepository); 
		 validateCodeFiler.setYichaoAuthenticationFailuHandler(yichaoAuthenticationFailuHandler);
		 validateCodeFiler.setSecurityPeoperties(securityPeoperties);
		 validateCodeFiler.afterPropertiesSet();
		 //短信验证码 浏览器基于session开发
		 SmsValidateCodeFiler smsValidateCodeFiler = new SmsValidateCodeFiler(sessionCodeRepository); 
		 smsValidateCodeFiler.setYichaoAuthenticationFailuHandler(yichaoAuthenticationFailuHandler);
		 smsValidateCodeFiler.setSecurityPeoperties(securityPeoperties);
		 //调用前置方法
		 smsValidateCodeFiler.afterPropertiesSet();
		 http
		 	.addFilterBefore(validateCodeFiler, UsernamePasswordAuthenticationFilter.class)
		 	.addFilterBefore(smsValidateCodeFiler, UsernamePasswordAuthenticationFilter.class)
		 	.formLogin()
		 		 
			 	.loginPage(ProjectConstant.LOGIN_JUMP_CONTROLLER)
			 	.loginProcessingUrl(ProjectConstant.LOGIN_URL)
			 	.successHandler(yichaoAuthenticationSuccessHandler)
			 	.failureHandler(yichaoAuthenticationFailuHandler)
			.and()
				//配置第三方联合登录
				.apply(securitySocialConfigurer)
			//配置记住我
			.and()
				//记住我
				.rememberMe()
				//设置User服务器
				.userDetailsService(myUserDetailsServcie)
				//设置token过期时间
				.tokenValiditySeconds(securityPeoperties.getBrowser().getRememberMeSeconds())
				//设置仓库可以进行记住我,cookie=>读取数据库=>标记登录=>实现记住我
				.tokenRepository(persistentTokenRepository())
			.and()
				.sessionManagement()
				//session失效设置
				//.invalidSessionUrl(securityPeoperties.getSession().getSessoinInvalidPage())
				//session最大存在数量设置 不允许同时登录两个
				.maximumSessions(securityPeoperties.getSession().getMaximumSessions())
				//不允许其他地方登录
				.maxSessionsPreventsLogin(securityPeoperties.getSession().isMaxSessionsPreventsLogin())
				//并发登录信息登录 
				.expiredSessionStrategy(sessionInformationExpiredStrategy)
			.and()
			.and()
				.logout()
				//退出URL
				.logoutUrl("/signOut")
				//退出成功
				//.logoutSuccessUrl(logoutSuccessUrl)
				.logoutSuccessHandler(logoutSuccessHandler)
		 	.and()
		 	.apply(smsAuthentioncationSecurityConfig)
		 	.and()
		 		.csrf()
		 		.disable();//加入手机验证码
		 authorizeConfigManager.config(http.authorizeRequests());
	}
}
