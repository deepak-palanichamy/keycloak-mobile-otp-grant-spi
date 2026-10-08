package com.gatehub.keycloak.grant;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import org.apache.http.HttpStatus;
import org.keycloak.OAuthErrorException;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.grants.OAuth2GrantTypeBase;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.util.DefaultClientSessionContext;
import org.keycloak.urls.UrlType;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.MediaType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.google.i18n.phonenumbers.PhoneNumberUtil.PhoneNumberFormat;
import com.google.i18n.phonenumbers.PhoneNumberUtil.PhoneNumberType;
import com.google.i18n.phonenumbers.Phonenumber.PhoneNumber;

import jakarta.ws.rs.core.Response;

/**
 * Implements the mobile-number OTP OAuth 2.0 grant for Keycloak.
 *
 * <p>
 * The grant validates a regional mobile number, verifies its OTP with an
 * external service, looks up the matching Keycloak user by mobile number, and
 * returns standard Keycloak tokens.
 * </p>
 */
public class MobileNumberOTPGrantType extends OAuth2GrantTypeBase {

    private static final Logger logger = LoggerFactory.getLogger(MobileNumberOTPGrantType.class);
    private static final Set<String> SUCCESS_STATUSES = Set.of("VERIFIED", "ALREADY_VERIFIED");
    private static final PhoneNumberUtil PHONE_NUMBER_UTIL = PhoneNumberUtil.getInstance();
    private static final int DEFAULT_HTTP_CONNECT_TIMEOUT_INSEC = 5;
    private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(DEFAULT_HTTP_CONNECT_TIMEOUT_INSEC))
            .build();

    private final URI otpVerifyUri;
    private final String sharedSecret;
    private final Duration requestTimeout;

    /**
     * Creates a grant handler configured for the external OTP service.
     *
     * @param otpVerifyUri   URI of the HTTPS OTP verification endpoint
     * @param sharedSecret   secret sent in the endpoint's authorization header
     * @param requestTimeout maximum duration allowed for an OTP verification
     *                       request
     */
    public MobileNumberOTPGrantType(URI otpVerifyUri, String sharedSecret, Duration requestTimeout) {
        this.otpVerifyUri = otpVerifyUri;
        this.sharedSecret = sharedSecret;
        this.requestTimeout = requestTimeout;
    }

    /**
     * Returns the Keycloak event type recorded for this grant.
     *
     * @return the login event type
     */
    @Override
    public EventType getEventType() {
        return EventType.LOGIN;
    }

    /**
     * Returns token parameters not consumed by this grant.
     *
     * @return an empty set because this grant defines no additional token
     *         parameters
     */
    @Override
    public Set<String> getTokenParameterNames() {
        return Collections.emptySet();
    }

    /**
     * Processes a mobile-number OTP grant request and creates the user's
     * authenticated Keycloak session and token response.
     *
     * @param context current Keycloak grant request context
     * @return the OAuth token response
     * @throws CorsErrorResponseException if request data is invalid, the OTP is
     *                                    rejected, or the user or external OTP
     *                                    service cannot be processed
     */
    @Override
    public Response process(Context context) {
        setContext(context);
        checkClient();

        String regionCode = formParams.getFirst("region_code");
        String mobileNumber = formParams.getFirst("mobile_number");
        String otp = formParams.getFirst("otp");
        String transId = formParams.getFirst("transaction_id");

        String scope = formParams.getFirst("scope");

        // 1. Validate Input
        if (mobileNumber == null || otp == null) {
            event.error(Errors.INVALID_REQUEST);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST,
                    "Missing mobile_number or otp", Response.Status.BAD_REQUEST);
        }

        // 2. Validate Mobile Number with E164 Spec
        regionCode = regionCode == null ? null : regionCode.trim().toUpperCase(Locale.ROOT);
        if (regionCode == null || !PHONE_NUMBER_UTIL.getSupportedRegions().contains(regionCode)) {
            event.error(Errors.INVALID_REQUEST);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST,
                    "Missing or Invalid region_code", Response.Status.BAD_REQUEST);
        }

        String e164Number;

        try {
            e164Number = validateAndNormalizeMobileNumber(mobileNumber, regionCode);
        } catch (IllegalArgumentException e) {
            event.error(Errors.INVALID_REQUEST);
            throw new CorsErrorResponseException(
                    cors,
                    OAuthErrorException.INVALID_REQUEST,
                    e.getMessage(),
                    Response.Status.BAD_REQUEST);
        }

        // 3. Verify OTP with your Custom Auth Service
        if (!verifyOtpWithCustomAuthService(regionCode, e164Number, otp, transId)) {
            event.error(Errors.INVALID_USER_CREDENTIALS);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT,
                    "Invalid or expired OTP", Response.Status.UNAUTHORIZED);
        }

        // 4. Find the User
        UserModel user = resolveUser(e164Number);

        if (!user.isEnabled()) {
            event.user(user);
            event.error(Errors.USER_DISABLED);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT,
                    "Account is disabled", Response.Status.BAD_REQUEST);
        }

        // 5. Create Keycloak Sessions
        UserSessionModel userSession = session.sessions().createUserSession(
                null,
                realm,
                user,
                user.getUsername(),
                context.getClientConnection().getRemoteAddr(),
                "urn:custom:mobilenumber_otp",
                false,
                null,
                null,
                UserSessionModel.SessionPersistenceState.PERSISTENT);
        userSession.setNote("otp_verified", e164Number);

        AuthenticatedClientSessionModel clientSession = session.sessions().createClientSession(realm, client,
                userSession);
        String issuer = session.getContext()
                .getUri(UrlType.FRONTEND)
                .getBaseUriBuilder()
                .path("realms")
                .path(realm.getName())
                .build()
                .toString();

        clientSession.setNote(OIDCLoginProtocol.ISSUER, issuer);
        clientSession.setNote(OIDCLoginProtocol.SCOPE_PARAM, scope);
        clientSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);

        // 6. Generate and Return standard OAuth Tokens
        ClientSessionContext clientSessionCtx = DefaultClientSessionContext.fromClientSessionAndScopeParameter(
                clientSession, scope, session);
        updateUserSessionFromClientAuth(userSession);

        event.user(user)
                .session(userSession)
                .detail(Details.AUTH_METHOD, "mobilenumber_otp")
                .detail(Details.USERNAME, user.getId());

        return createTokenResponse(user, userSession, clientSessionCtx, scope, false, null);
    }

    public static String validateAndNormalizeMobileNumber(String mobileNumber, String regionCode) {
        if (mobileNumber == null || mobileNumber.isBlank()) {
            throw new IllegalArgumentException("Missing mobile_number");
        }

        String normalizedRegionCode = regionCode == null ? null : regionCode.trim().toUpperCase(Locale.ROOT);
        if (normalizedRegionCode == null || normalizedRegionCode.isBlank()
                || !PHONE_NUMBER_UTIL.getSupportedRegions().contains(normalizedRegionCode)) {
            throw new IllegalArgumentException("Missing or Invalid region_code");
        }

        try {
            PhoneNumber parsed = PHONE_NUMBER_UTIL.parse(mobileNumber.trim(), normalizedRegionCode);
            if (PHONE_NUMBER_UTIL.getNumberType(parsed) != PhoneNumberType.MOBILE
                    || !PHONE_NUMBER_UTIL.isValidNumberForRegion(parsed, normalizedRegionCode)) {
                throw new IllegalArgumentException("Invalid mobile number");
            }
            return PHONE_NUMBER_UTIL.format(parsed, PhoneNumberFormat.E164);
        } catch (NumberParseException e) {
            throw new IllegalArgumentException("Invalid mobile number", e);
        }
    }

    /**
     * Finds the user associated with a canonical mobile number.
     *
     * @param mobileNumber canonical E.164 mobile number
     * @return the existing user
     * @throws CorsErrorResponseException if no user is found with the mobile number
     */
    private UserModel resolveUser(String mobileNumber) {
        return getUniqueUserByAttribute("mobileNumber", mobileNumber)
                .orElseThrow(() -> {
                    event.error(Errors.USER_NOT_FOUND);
                    return new CorsErrorResponseException(
                            cors,
                            OAuthErrorException.INVALID_GRANT,
                            "User not found",
                            Response.Status.BAD_REQUEST);
                });
    }

    /**
     * Finds the first user whose attribute matches the supplied value.
     *
     * @param attribute user attribute name
     * @param value     attribute value
     * @return an optional matching user
     */
    private Optional<UserModel> getUniqueUserByAttribute(String attribute, String value) {
        return session.users().searchForUserByUserAttributeStream(realm, attribute, value)
                .filter(Objects::nonNull)
                .findFirst();
    }

    /**
     * Verifies an OTP through the configured external service.
     *
     * @param mobileNumber canonical E.164 mobile number
     * @param otp          one-time password to verify
     * @return {@code true} when the service returns a successful verification
     *         status
     * @throws CorsErrorResponseException if the service times out, cannot be
     *                                    reached, or fails unexpectedly
     */
    private boolean verifyOtpWithCustomAuthService(String countryIso, String mobileNumber, String otp,
            String transactionId) {
        try {
            Map<String, String> payload = new HashMap<>();
            payload.put("countryIso", countryIso);
            payload.put("mobileNumber", mobileNumber);
            payload.put("otp", otp);
            if (transactionId != null) {
                payload.put("transactionId", transactionId);
            }
            String requestBodyJson = JsonSerialization.writeValueAsString(payload);

            HttpRequest request = HttpRequest.newBuilder()
                    .timeout(requestTimeout)
                    .uri(otpVerifyUri)
                    .header("Content-Type", MediaType.APPLICATION_JSON)
                    .header("X-Internal-Secret", sharedSecret)
                    .POST(HttpRequest.BodyPublishers.ofString(requestBodyJson))
                    .build();

            HttpResponse<String> response = HTTP_CLIENT.send(request,
                    HttpResponse.BodyHandlers.ofString());

            // Returns true only if your service responds with 200 OK and
            // 'VERIFIED'/'ALREADY_VERIFIED' body
            // Return false for any-other status-code
            String responseBody = response.body();
            if (responseBody == null || responseBody.isBlank()) {
                logger.info("OTP verification failed. Empty response body");
                return false;
            }

            String verificationStatus = responseBody.trim();
            if ((response.statusCode() == HttpStatus.SC_OK)
                    && SUCCESS_STATUSES.contains(verificationStatus)) {
                logger.info("OTP verification successful. status: {}", verificationStatus);
                return true;
            } else {
                logger.info("OTP verification failed. status: {}", verificationStatus);
                return false;
            }

        } catch (HttpTimeoutException e) {
            logger.warn("OTP verification service timed out", e);
            throw new CorsErrorResponseException(cors, OAuthErrorException.SERVER_ERROR,
                    "OTP verification service timed out", Response.Status.GATEWAY_TIMEOUT);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logger.warn("OTP verification request was interrupted", e);
            throw new CorsErrorResponseException(cors, OAuthErrorException.SERVER_ERROR,
                    "OTP verification request was interrupted", Response.Status.INTERNAL_SERVER_ERROR);
        } catch (IOException e) {
            logger.warn("Unable to reach OTP verification service", e);
            throw new CorsErrorResponseException(cors, OAuthErrorException.SERVER_ERROR,
                    "Unable to reach OTP verification service", Response.Status.BAD_GATEWAY);
        } catch (RuntimeException e) {
            logger.error("Unexpected error while verifying OTP", e);
            throw new CorsErrorResponseException(cors, OAuthErrorException.SERVER_ERROR,
                    "An unexpected error occurred during OTP verification", Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

}
