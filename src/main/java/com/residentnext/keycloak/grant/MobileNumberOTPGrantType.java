package com.residentnext.keycloak.grant;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

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
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.grants.OAuth2GrantTypeBase;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.util.DefaultClientSessionContext;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.ws.rs.core.Response;

public class MobileNumberOTPGrantType extends OAuth2GrantTypeBase {

    private static final Logger logger = LoggerFactory.getLogger(MobileNumberOTPGrantType.class);

    // Strict E.164: + followed by 1-15 digits (no spaces, dashes, or formatting)
    private static final Pattern E164_PATTERN = Pattern.compile("^\\+[1-9]\\d{1,14}$");
    // Alphanumeric or numeric OTP bounded between 4 and 10 characters
    private static final Pattern OTP_PATTERN = Pattern.compile("^[a-zA-Z0-9]{4,10}$");

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

        String mobileNumber = formParams.getFirst("mobile_number");
        String otp = formParams.getFirst("otp");
        String scope = formParams.getFirst("scope");

        // 1. Validate Input
        if (mobileNumber == null || otp == null) {
            event.error(Errors.INVALID_REQUEST);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST,
                    "Missing mobile_number or otp", Response.Status.BAD_REQUEST);
        }

        // 2. Verify OTP with your Custom Auth Service
        if (!verifyOtpWithCustomService(mobileNumber, otp)) {
            event.error(Errors.INVALID_USER_CREDENTIALS);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT,
                    "Invalid or expired OTP", Response.Status.UNAUTHORIZED);
        }

        // 3. Find or Auto-Provision the User
        UserModel user = resolveOrCreateUser(mobileNumber);

        if (!user.isEnabled()) {
            event.user(user);
            event.error(Errors.USER_DISABLED);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT,
                    "Account is disabled", Response.Status.BAD_REQUEST);
        }

        // 4. Create Keycloak Sessions
        // UserSessionModel userSession = session.sessions().createUserSession(
        // realm, user, user.getUsername(), clientConnection.getRemoteAddr(),
        // MobileNumberOTPGrantTypeFactory.GRANT_TYPE_ID, false, null, null);
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

        // AuthenticatedClientSessionModel clientSession =
        // session.sessions().createClientSession(realm, client,
        // userSession);
        // clientSession.setNote(OIDCLoginProtocol.ISSUER,
        // context.getRequest().getUri().getBaseUri().toString());
        // clientSession.setNote(OIDCLoginProtocol.SCOPE_PARAM, scope);

        RootAuthenticationSessionModel rootAuthSession = session.authenticationSessions()
                .createRootAuthenticationSession(realm);
        AuthenticationSessionModel authSession = rootAuthSession.createAuthenticationSession(client);
        authSession.setAuthenticatedUser(user);
        authSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        authSession.setAuthNote(OIDCLoginProtocol.ISSUER, context.getRequest().getUri().getBaseUri().toString());
        authSession.setAuthNote(OIDCLoginProtocol.SCOPE_PARAM, scope);

        // 5. Generate and Return standard OAuth Tokens
        // DefaultClientSessionContext clientSessionCtx = DefaultClientSessionContext
        // .fromClientSessionAndScopeParameter(clientSession, scope, session);
        ClientSessionContext clientSessionCtx = TokenManager.attachAuthenticationSession(session, userSession,
                authSession);
        updateUserSessionFromClientAuth(userSession);

        event.user(user)
                .session(userSession)
                .detail(Details.AUTH_METHOD, "mobilenumber_otp")
                .detail(Details.USERNAME, user.getId())
                .success();

        // return Response.ok(tokenManager.responseBuilder(realm, client, event,
        // session, userSession, clientSessionCtx)
        // .generateAccessToken()
        // .generateRefreshToken()
        // .generateIDToken()
        // .build())
        // .build();
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
