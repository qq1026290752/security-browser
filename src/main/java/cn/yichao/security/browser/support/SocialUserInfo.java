package cn.yichao.security.browser.support;

import lombok.Data;

@Data
public class SocialUserInfo {
	//应用ID
	private String providerId;	
	//用户ID
	private String providerUserId;
	//用户昵称
	private String nikeName;
	//用户头像
	private String headUrl;
	
}
