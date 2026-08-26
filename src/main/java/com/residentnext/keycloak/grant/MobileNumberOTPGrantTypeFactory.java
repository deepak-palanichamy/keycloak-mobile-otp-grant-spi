package com.residentnext.keycloak.grant;

import java.net.URI;
import java.time.Duration;

import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;
import org.keycloak.protocol.oidc.grants.OAuth2GrantTypeFactory;

/**
 * Creates and configures instances of the mobile-number OTP grant for Keycloak.
 */
public class MobileNumberOTPGrantTypeFactory implements OAuth2GrantTypeFactory {

    public static final String GRANT_TYPE_ID = "urn:custom:mobilenumber_otp";
    public static final String GRANT_TYPE_SHORTCUT = "mno";

    private URI otpVerifyUri;
    private String sharedSecret;
    private Duration requestTimeout;

    @Override
    /**
     * Creates a grant instance using the factory's configured OTP service settings.
     *
     * @param session current Keycloak session
     * @return a configured mobile-number OTP grant
     */
    public OAuth2GrantType create(KeycloakSession session) {
        return new MobileNumberOTPGrantType(otpVerifyUri, sharedSecret, requestTimeout);
    }

    @Override
    /**
     * Loads the OTP service URI, shared secret, and request timeout from Keycloak
     * configuration or their environment-variable fallbacks.
     *
     * @param config provider configuration scope
     * @throws IllegalStateException if the endpoint or shared secret is missing
     * @throws IllegalArgumentException if the endpoint URI is invalid
     */
    public void init(Scope config) {
        // Reads from keycloak.conf (spi-oauth2-grant-type-urn-custom-mobile-otp-*) or
        // env vars
        String urlStr = config.get("verify-url", System.getenv("KC_OTP_VERIFY_URL"));
        this.sharedSecret = config.get("shared-secret", System.getenv("KC_OTP_SHARED_SECRET"));
        int timeoutSec = config.getInt("timeout-seconds", 5);
        this.requestTimeout = Duration.ofSeconds(timeoutSec);

        if (urlStr == null || this.sharedSecret == null) {
            throw new IllegalStateException("Mobile OTP SPI: Both verify-url and shared-secret must be configured.");
        }

        this.otpVerifyUri = URI.create(urlStr);
        if (!"https".equalsIgnoreCase(this.otpVerifyUri.getScheme())) {
            throw new IllegalStateException("Mobile OTP SPI: verify-url MUST use HTTPS protocol.");
        }
    }

    @Override
    /**
     * Performs post-initialization work after all Keycloak providers are loaded.
     *
     * @param factory Keycloak session factory
     */
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    /**
     * Releases factory resources. This implementation has no resources to close.
     */
    public void close() {
    }

    @Override
    /**
     * Returns the fully qualified identifier used to register this grant type.
     *
     * @return the custom grant type identifier
     */
    public String getId() {
        return GRANT_TYPE_ID;
    }

    @Override
    /**
     * Returns the short form accepted for this grant type.
     *
     * @return the grant shortcut
     */
    public String getShortcut() {
        return GRANT_TYPE_SHORTCUT;
    }

}
