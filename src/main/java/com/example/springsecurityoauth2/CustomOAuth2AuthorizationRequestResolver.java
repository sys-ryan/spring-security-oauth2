package com.example.springsecurityoauth2;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

public class CustomOAuth2AuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

    private ClientRegistrationRepository clientRegistrationRepository;
    private String baseUri;

    private static final String REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId";

    private static final Consumer<OAuth2AuthorizationRequest.Builder> DEFAULT_PKCE_APPLIER = OAuth2AuthorizationRequestCustomizers
            .withPkce();

    private DefaultOAuth2AuthorizationRequestResolver defaultResolver;

    private final AntPathRequestMatcher authorizationRequestMatcher;


    public CustomOAuth2AuthorizationRequestResolver(
            ClientRegistrationRepository clientRegistrationRepository,
            String baseUri
    ) {
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.authorizationRequestMatcher = new AntPathRequestMatcher(
                baseUri + "/{" + REGISTRATION_ID_URI_VARIABLE_NAME + "}"
        );

        defaultResolver = new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, baseUri);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        String registrationId = resolveRegistrationId(request);
        if(registrationId == null) {
            return null;
        }

        if(registrationId.equals("keycloakWithPKCE")) {
            OAuth2AuthorizationRequest oAuth2AuthorizationRequest = defaultResolver.resolve(request);
            return customResolve(oAuth2AuthorizationRequest, registrationId);
        }

        return defaultResolver.resolve(request);
    }


    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        String registrationId = resolveRegistrationId(request);
        if(registrationId == null) {
            return null;
        }

        if(registrationId.equals("keycloakWithPKCE")) {
            OAuth2AuthorizationRequest oAuth2AuthorizationRequest = defaultResolver.resolve(request);
            return customResolve(oAuth2AuthorizationRequest, clientRegistrationId);
        }

        return defaultResolver.resolve(request);
    }

    private OAuth2AuthorizationRequest customResolve(OAuth2AuthorizationRequest oAuth2AuthorizationRequest, String clientRegistrationId)  {

        Map<String, Object> extraParam = new HashMap<>();
        extraParam.put("customName1", "customValue1");
        extraParam.put("customName2", "customValue2");
        extraParam.put("customName3", "customValue3");

        OAuth2AuthorizationRequest.Builder builder = OAuth2AuthorizationRequest
                .from(oAuth2AuthorizationRequest)
                .additionalParameters(extraParam )
                ;
        DEFAULT_PKCE_APPLIER.accept(builder);

        return builder.build();
    }

    private String resolveRegistrationId(HttpServletRequest request) {
        if (this.authorizationRequestMatcher.matches(request)) {
            return this.authorizationRequestMatcher.matcher(request)
                    .getVariables()
                    .get(REGISTRATION_ID_URI_VARIABLE_NAME);
        }
        return null;
    }
}
