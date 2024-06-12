package com.example.security1.config.oauth;

import com.example.security1.UserRepository;
import com.example.security1.config.auth.PrincipalDetails;
import com.example.security1.config.oauth.provider.FacebookUserInfo;
import com.example.security1.config.oauth.provider.GoogleUserInfo;
import com.example.security1.config.oauth.provider.NaverUserInfo;
import com.example.security1.config.oauth.provider.OAuth2UserInfo;
import com.example.security1.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private UserRepository userRepository;
    //구글로부터 받은 userRequest 데이터에 대한 후처리 함수


    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest){
        //구글로그인 완료 -> code를 리턴 -> accessToken 요청
        //userRequest정보 -> 회원프로필 받아야함(loadUser) -> 프로필
        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println("userRequest:"+userRequest);
        System.out.println("attributes:"+oAuth2User.getAttributes());
        OAuth2UserInfo oAuth2UserInfo = null;
        if (userRequest.getClientRegistration().getRegistrationId().equals("google")){
            System.out.println("구글 로그인 요청");
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        }else if(userRequest.getClientRegistration().getRegistrationId().equals("facebook")){
            System.out.println("페이스북 로그인 요청");
            oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
        }else if(userRequest.getClientRegistration().getRegistrationId().equals("naver")){
            System.out.println("네이버 로그인 요청");
            oAuth2UserInfo = new NaverUserInfo((Map) oAuth2User.getAttributes().get("response"));
        }else{
            System.out.println("구글, 페이스북, 네이버 로그인만 지원합니다.");
        }

        String provider = oAuth2UserInfo.getProvider(); //google
        String providerId = oAuth2UserInfo.getProviderId();
        String username = provider+"_"+providerId;
        String password = "1234";
        String email = oAuth2UserInfo.getEmail();
        String role = "ROLE_USER";
        User userEntity = userRepository.findByUsername(username);

        if(userEntity == null){
            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        }
        return new PrincipalDetails(userEntity,oAuth2User.getAttributes());

    }
}
