package com.gatehub.keycloak.grant;

import java.net.URI;
import java.time.Duration;

import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;
import org.keycloak.protocol.oidc.grants.OAuth2GrantTypeFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Creates and configures instances of the mobile-number OTP grant for Keycloak.
 */
public class MobileNumberOTPGrantTypeFactory implements OAuth2GrantTypeFactory {

    private static final Logger logger = LoggerFactory.getLogger(MobileNumberOTPGrantTypeFactory.class);

    public static final String GRANT_TYPE_ID = "urn:custom:mobilenumber_otp";
    public static final String GRANT_TYPE_SHORTCUT = "mno";
    public static final int DEFAULT_REQUEST_TIMEOUT_INSEC = 30;

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
     * @throws IllegalStateException    if the endpoint or shared secret is missing
     * @throws IllegalArgumentException if the endpoint URI is invalid
     */
    public void init(Scope config) {
        // Reads from keycloak.conf (spi-oauth2-grant-type-urn-custom-mobile-otp-*) or
        // env vars
        String urlStr = config.get("validation-url", System.getenv("KC_USER_OTP_VALIDATION_URL"));
        this.sharedSecret = config.get("shared-secret", System.getenv("KC_USER_OTP_SHARED_SECRET"));
        String timeoutSec = config.get("timeout-seconds", System.getenv("KC_USER_OTP_TIMEOUT_SECONDS"));
        this.requestTimeout = Duration.ofSeconds(parseTimeoutSeconds(timeoutSec));

        if (urlStr == null || this.sharedSecret == null) {
            throw new IllegalStateException(
                    "Mobile OTP SPI: Both validation-url and shared-secret must be configured.");
        }

        this.otpVerifyUri = URI.create(urlStr);
        if (!"https".equalsIgnoreCase(this.otpVerifyUri.getScheme())) {
            throw new IllegalStateException("Mobile OTP SPI: validation-url MUST use HTTPS protocol.");
        }
    }

    /**
     * Parses the configured request timeout, falling back to
     * {@link #DEFAULT_REQUEST_TIMEOUT_INSEC} when it is unset, blank, not a
     * number, or not positive.
     *
     * @param timeoutSec configured timeout in seconds, possibly {@code null}
     * @return the timeout in seconds to use
     */
    static int parseTimeoutSeconds(String timeoutSec) {
        if (timeoutSec == null || timeoutSec.isBlank()) {
            return DEFAULT_REQUEST_TIMEOUT_INSEC;
        }
        try {
            int parsed = Integer.parseInt(timeoutSec.trim());
            if (parsed > 0) {
                return parsed;
            }
        } catch (NumberFormatException e) {
            // fall through to the default below
        }
        logger.warn("Mobile OTP SPI: Invalid timeout-seconds '{}' configured, using default value {} seconds.",
                timeoutSec, DEFAULT_REQUEST_TIMEOUT_INSEC);
        return DEFAULT_REQUEST_TIMEOUT_INSEC;
    }

    /**
     * Performs post-initialization work after all Keycloak providers are loaded.
     *
     * @param factory Keycloak session factory
     */
    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    /**
     * Releases factory resources. This implementation has no resources to close.
     */
    @Override
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
