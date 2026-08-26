package com.residentnext.keycloak.grant;

import java.net.URI;
import java.time.Duration;

import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;
import org.keycloak.protocol.oidc.grants.OAuth2GrantTypeFactory;

public class MobileNumberOTPGrantTypeFactory implements OAuth2GrantTypeFactory {

    public static final String GRANT_TYPE_ID = "urn:custom:mobilenumber_otp";
    public static final String GRANT_TYPE_SHORTCUT = "mno";

    private URI otpVerifyUri;
    private String sharedSecret;
    private Duration requestTimeout;

    @Override
    public OAuth2GrantType create(KeycloakSession session) {
        return new MobileNumberOTPGrantType(otpVerifyUri, sharedSecret, requestTimeout);
    }

    @Override
    public void init(Scope config) {
        // Reads from keycloak.conf (spi-oauth2-grant-type-urn-custom-mobile-otp-*) or
        // env vars
        String urlStr = config.get("verify-url", System.getenv("KC_OTP_VERIFY_URL"));
        this.sharedSecret = config.get("shared-secret", System.getenv("KC_OTP_SHARED_SECRET"));
        int timeoutSec = config.getInt("timeout-seconds", 5);

        if (urlStr == null || this.sharedSecret == null) {
            throw new IllegalStateException("Mobile OTP SPI: Both verify-url and shared-secret must be configured.");
        }

        this.otpVerifyUri = URI.create(urlStr);
        if (!"https".equalsIgnoreCase(this.otpVerifyUri.getScheme())) {
            throw new IllegalStateException("Mobile OTP SPI: verify-url MUST use HTTPS protocol.");
        }
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return GRANT_TYPE_ID;
    }

    @Override
    public String getShortcut() {
        return GRANT_TYPE_SHORTCUT;
    }

}
