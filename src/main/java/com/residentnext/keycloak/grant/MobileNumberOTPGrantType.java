package com.residentnext.keycloak.grant;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.Collections;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.apache.http.HttpStatus;
import org.keycloak.OAuthErrorException;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.grants.OAuth2GrantTypeBase;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.util.DefaultClientSessionContext;
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
 * <p>The grant validates a regional mobile number, verifies its OTP with an
 * external service, provisions a matching Keycloak user when necessary, and
 * returns standard Keycloak tokens.</p>
 */
public class MobileNumberOTPGrantType extends OAuth2GrantTypeBase {

    private static final Logger logger = LoggerFactory.getLogger(MobileNumberOTPGrantType.class);
    private static final Set<String> SUCCESS_STATUSES = Set.of("VERIFIED", "ALREADY_VERIFIED");

    private final URI otpVerifyUri;
    private final String sharedSecret;
    private final Duration requestTimeout;
    // private final HttpClient httpClient;

    /**
     * Creates a grant handler configured for the external OTP service.
     *
     * @param otpVerifyUri URI of the HTTPS OTP verification endpoint
     * @param sharedSecret secret sent in the endpoint's authorization header
     * @param requestTimeout maximum duration allowed for an OTP verification request
     */
    public MobileNumberOTPGrantType(URI otpVerifyUri, String sharedSecret, Duration requestTimeout) {
        this.otpVerifyUri = otpVerifyUri;
        this.sharedSecret = sharedSecret;
        this.requestTimeout = requestTimeout;
    }

    // Reusing the Java 11+ HttpClient for external calls
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    @Override
    /**
     * Returns the Keycloak event type recorded for this grant.
     *
     * @return the login event type
     */
    public EventType getEventType() {
        return EventType.LOGIN;
    }

    @Override
    /**
     * Returns token parameters not consumed by this grant.
     *
     * @return an empty set because this grant defines no additional token parameters
     */
    public Set<String> getTokenParameterNames() {
        return Collections.emptySet();
    }

    @Override
    /**
     * Processes a mobile-number OTP grant request and creates the user's
     * authenticated Keycloak session and token response.
     *
     * @param context current Keycloak grant request context
     * @return the OAuth token response
     * @throws CorsErrorResponseException if request data is invalid, the OTP is
     *         rejected, or the user or external OTP service cannot be processed
     */
    public Response process(Context context) {
        setContext(context);
        checkClient();

        String countryIso = formParams.getFirst("country_iso");
        String mobileNumber = formParams.getFirst("mobile_number");

        String otp = formParams.getFirst("otp");
        String scope = formParams.getFirst("scope");

        PhoneNumberUtil phoneUtil = PhoneNumberUtil.getInstance();

        // 1. Validate Input
        if (mobileNumber == null || otp == null) {
            event.error(Errors.INVALID_REQUEST);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST,
                    "Missing mobile_number or otp", Response.Status.BAD_REQUEST);
        }

        // 2. Validate Mobile Number with E164 Spec
        countryIso = countryIso == null ? null : countryIso.trim().toUpperCase(Locale.ROOT);
        if (countryIso == null || !phoneUtil.getSupportedRegions().contains(countryIso)) {
            event.error(Errors.INVALID_REQUEST);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST,
                    "Missing or Invalid country_iso", Response.Status.BAD_REQUEST);
        }

        String e164Number = null;

        try {
            PhoneNumber parsed = phoneUtil.parse(mobileNumber, countryIso);
            if (!phoneUtil.isValidNumberForRegion(parsed, countryIso)
                    || phoneUtil.getNumberType(parsed) != PhoneNumberType.MOBILE) {
                event.error(Errors.INVALID_REQUEST);
                throw new CorsErrorResponseException(
                        cors,
                        OAuthErrorException.INVALID_REQUEST,
                        "Invalid mobile number",
                        Response.Status.BAD_REQUEST);
            }
            e164Number = phoneUtil.format(parsed, PhoneNumberFormat.E164);
        } catch (NumberParseException e) {
            event.error(Errors.INVALID_REQUEST);
            throw new CorsErrorResponseException(
                    cors,
                    OAuthErrorException.INVALID_REQUEST,
                    "Invalid mobile number",
                    Response.Status.BAD_REQUEST);
        }

        // 3. Verify OTP with your Custom Auth Service
        if (!verifyOtpWithCustomService(e164Number, otp)) {
            event.error(Errors.INVALID_USER_CREDENTIALS);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT,
                    "Invalid or expired OTP", Response.Status.UNAUTHORIZED);
        }

        // 4. Find or Auto-Provision the User
        UserModel user = resolveOrCreateUser(e164Number);

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

        AuthenticatedClientSessionModel clientSession = session.sessions().createClientSession(realm, client,
                userSession);
        clientSession.setNote(OIDCLoginProtocol.ISSUER,
                context.getRequest().getUri().getBaseUri().toString());
        clientSession.setNote(OIDCLoginProtocol.SCOPE_PARAM, scope);
        clientSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);

        // 6. Generate and Return standard OAuth Tokens
        ClientSessionContext clientSessionCtx = DefaultClientSessionContext.fromClientSessionAndScopeParameter(
                clientSession, scope, session);
        updateUserSessionFromClientAuth(userSession);

        event.user(user)
                .session(userSession)
                .detail(Details.AUTH_METHOD, "mobilenumber_otp")
                .detail(Details.USERNAME, user.getId())
                .success();

        return createTokenResponse(user, userSession, clientSessionCtx, scope, false, null);
    }

    /**
     * Finds the user associated with a canonical mobile number or provisions a
     * new enabled user when no match exists.
     *
     * @param mobileNumber canonical E.164 mobile number
     * @return the existing or newly created user
     * @throws CorsErrorResponseException if a concurrent creation conflict
     *         cannot be resolved
     */
    private UserModel resolveOrCreateUser(String mobileNumber) {
        // UserModel user = session.users().getUserByUsername(realm, canonicalPhone);
        UserModel user = null;
        Optional<UserModel> optUser = getUniqueUserByAttribute("mobileNumber", mobileNumber);
        if (optUser.isPresent()) {
            user = optUser.get();
            return user;
        }

        try {
            String userId = UUID.randomUUID().toString();
            user = session.users().addUser(realm, userId);
            user.setEnabled(true);
            user.setSingleAttribute("mobileNumber", mobileNumber);
            return user;
        } catch (ModelDuplicateException e) {
            // Concurrent request created user between our read and write; fetch again
            logger.warn("Concurrent user creation conflict for {0}. Retrying lookup.", mobileNumber);
            Optional<UserModel> optUserRecheck = getUniqueUserByAttribute("mobileNumber", mobileNumber);
            if (optUserRecheck.isPresent()) {
                user = optUserRecheck.get();
                return user;
            }
            throw new CorsErrorResponseException(cors, OAuthErrorException.SERVER_ERROR,
                    "Unable to resolve user profile", Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Finds the first user whose attribute matches the supplied value.
     *
     * @param attribute user attribute name
     * @param value attribute value
     * @return an optional matching user
     */
    private Optional<UserModel> getUniqueUserByAttribute(String attribute, String value) {
        Optional<UserModel> optUser = session.users().searchForUserByUserAttributeStream(realm, attribute, value)
                .findFirst();
        return optUser;
    }

    /**
     * Verifies an OTP through the configured external service.
     *
     * @param mobileNumber canonical E.164 mobile number
     * @param otp one-time password to verify
     * @return {@code true} when the service returns a successful verification status
     * @throws CorsErrorResponseException if the service times out, cannot be
     *         reached, or fails unexpectedly
     */
    private boolean verifyOtpWithCustomService(String mobileNumber, String otp) {
        try {
            String requestBodyJson = JsonSerialization.writeValueAsString(Map.of(
                    "mobile_number", mobileNumber,
                    "otp", otp));

            HttpRequest request = HttpRequest.newBuilder()
                    .timeout(requestTimeout)
                    .uri(otpVerifyUri)
                    .header("Content-Type", MediaType.APPLICATION_JSON)
                    .header("Authorization", "Bearer " + sharedSecret)
                    .POST(HttpRequest.BodyPublishers.ofString(requestBodyJson))
                    .build();

            HttpResponse<String> response = httpClient.send(request,
                    HttpResponse.BodyHandlers.ofString());

            // Returns true only if your service responds with 200 OK and
            // 'VERIFIED'/'ALREADY_VERIFIED' body
            // Return false for any-other status-code
            String verificationStatus = response.body().trim();
            if ((response.statusCode() == HttpStatus.SC_OK)
                    && SUCCESS_STATUSES.contains(verificationStatus)) {
                logger.info("OTP verification successful. status: {}", verificationStatus);
                return true;
            } else {
                logger.info("OTP verification failed. status: {}", verificationStatus);
                return false;
            }

        } catch (HttpTimeoutException e) {
            logger.warn("OTP verification service timed out for mobile number {}", mobileNumber, e);
            throw new CorsErrorResponseException(cors, OAuthErrorException.SERVER_ERROR,
                    "OTP verification service timed out", Response.Status.GATEWAY_TIMEOUT);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logger.warn("OTP verification request was interrupted for mobile number {}", mobileNumber, e);
            throw new CorsErrorResponseException(cors, OAuthErrorException.SERVER_ERROR,
                    "OTP verification request was interrupted", Response.Status.INTERNAL_SERVER_ERROR);
        } catch (IOException e) {
            logger.warn("Unable to reach OTP verification service for mobile number {}", mobileNumber, e);
            throw new CorsErrorResponseException(cors, OAuthErrorException.SERVER_ERROR,
                    "Unable to reach OTP verification service", Response.Status.BAD_GATEWAY);
        } catch (RuntimeException e) {
            logger.error("Unexpected error while verifying OTP for mobile number {}", mobileNumber, e);
            throw new CorsErrorResponseException(cors, OAuthErrorException.SERVER_ERROR,
                    "Unable to verify OTP", Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

}
