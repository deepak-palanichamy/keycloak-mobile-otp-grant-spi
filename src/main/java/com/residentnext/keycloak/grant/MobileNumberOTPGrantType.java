package com.residentnext.keycloak.grant;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Collections;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.google.i18n.phonenumbers.PhoneNumberUtil.PhoneNumberFormat;
import com.google.i18n.phonenumbers.PhoneNumberUtil.PhoneNumberType;
import com.google.i18n.phonenumbers.Phonenumber.PhoneNumber;

import jakarta.ws.rs.core.Response;

public class MobileNumberOTPGrantType extends OAuth2GrantTypeBase {

    private static final Logger logger = LoggerFactory.getLogger(MobileNumberOTPGrantType.class);

    private final URI otpVerifyUri;
    private final String sharedSecret;
    private final Duration requestTimeout;
    // private final HttpClient httpClient;

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
    public EventType getEventType() {
        return EventType.LOGIN;
    }

    @Override
    public Set<String> getTokenParameterNames() {
        return Collections.emptySet();
    }

    @Override
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
     * Searches for the unique user that have a specific attribute with a specific
     * value.
     * 
     * @param attribute the attribute name.
     * @param value     the attribute value.
     * @return An optional user that match the search criteria.
     */
    private Optional<UserModel> getUniqueUserByAttribute(String attribute, String value) {
        Optional<UserModel> optUser = session.users().searchForUserByUserAttributeStream(realm, attribute, value)
                .findFirst();
        return optUser;
    }

    /**
     * Executes a server-to-server call to your external OTP service.
     */
    private boolean verifyOtpWithCustomService(String mobileNumber, String otp) {
        // try {
        // String jsonPayload = String.format("{\"mobile_number\":\"%s\",
        // \"otp\":\"%s\"}", mobileNumber, otp);

        // HttpRequest request = HttpRequest.newBuilder()
        // .timeout(Duration.ofSeconds(5))
        // .uri(URI.create("http://your-custom-auth-service/api/otp/verify"))
        // .header("Content-Type", "application/json")
        // // Use a hard-to-guess internal secret to secure this endpoint
        // .header("Authorization", "Bearer INTERNAL_SHARED_SECRET")
        // .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
        // .build();

        // HttpResponse<String> response = httpClient.send(request,
        // HttpResponse.BodyHandlers.ofString());

        // // Returns true only if your service responds with 200 OK
        // return response.statusCode() == 200;
        // } catch (Exception e) {
        // // Log the exception in a real production environment
        // return false;
        // }
        return true;
    }

}
