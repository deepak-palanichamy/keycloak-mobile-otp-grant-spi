package com.residentnext.keycloak.grant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.stream.Stream;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.keycloak.OAuthErrorException;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.UserSessionProvider;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType.Context;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.cors.Cors;

import com.gatehub.keycloak.grant.MobileNumberOTPGrantType;
import com.sun.net.httpserver.HttpServer;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.RuntimeDelegate;

class MobileNumberOTPGrantTypeTest {

    private static HttpServer mockOtpServer;
    private static URI mockOtpUri;
    private static final String SHARED_SECRET = "test-secret";

    private KeycloakSession session;
    private KeycloakContext keycloakContext;
    private RealmModel realm;
    private ClientModel client;
    private UserProvider userProvider;
    private UserSessionProvider userSessionProvider;
    private EventBuilder event;
    private Cors cors;
    private ClientConnection clientConnection;
    private HttpRequest httpRequest;
    private KeycloakUriInfo uriInfo;
    private Context context;
    private MultivaluedMap<String, String> formParams;

    private TokenManager tokenManager;
    private MobileNumberOTPGrantType grantType;

    @BeforeAll
    static void startOtpServer() throws IOException {
        org.keycloak.common.Profile.defaults();

        RuntimeDelegate runtimeDelegate = mock(RuntimeDelegate.class);
        when(runtimeDelegate.createResponseBuilder()).thenAnswer(inv -> {
            Response.ResponseBuilder rb = mock(Response.ResponseBuilder.class);
            final int[] statusHolder = new int[] { 200 };
            final Object[] entityHolder = new Object[1];

            when(rb.status(anyInt())).thenAnswer(sInv -> {
                statusHolder[0] = sInv.getArgument(0);
                return rb;
            });
            when(rb.status(any(Response.StatusType.class))).thenAnswer(sInv -> {
                statusHolder[0] = ((Response.StatusType) sInv.getArgument(0)).getStatusCode();
                return rb;
            });
            when(rb.status(any(Response.Status.class))).thenAnswer(sInv -> {
                statusHolder[0] = ((Response.Status) sInv.getArgument(0)).getStatusCode();
                return rb;
            });
            when(rb.entity(any())).thenAnswer(eInv -> {
                entityHolder[0] = eInv.getArgument(0);
                return rb;
            });
            when(rb.type(any(MediaType.class))).thenReturn(rb);
            when(rb.type(anyString())).thenReturn(rb);

            when(rb.build()).thenAnswer(bInv -> {
                Response resp = mock(Response.class);
                when(resp.getStatus()).thenReturn(statusHolder[0]);
                when(resp.getEntity()).thenReturn(entityHolder[0]);
                return resp;
            });

            return rb;
        });
        RuntimeDelegate.setInstance(runtimeDelegate);

        mockOtpServer = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        mockOtpServer.createContext("/verify", exchange -> {
            byte[] responseBytes = "VERIFIED".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, responseBytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(responseBytes);
            }
        });
        mockOtpServer.start();
        int port = mockOtpServer.getAddress().getPort();
        mockOtpUri = URI.create("http://localhost:" + port + "/verify");
    }

    @AfterAll
    static void stopOtpServer() {
        if (mockOtpServer != null) {
            mockOtpServer.stop(0);
        }
    }

    @BeforeEach
    void setUp() {
        session = mock(KeycloakSession.class);
        keycloakContext = mock(KeycloakContext.class);
        realm = mock(RealmModel.class);
        client = mock(ClientModel.class);
        userProvider = mock(UserProvider.class);
        userSessionProvider = mock(UserSessionProvider.class);
        event = mock(EventBuilder.class);
        cors = mock(Cors.class);
        clientConnection = mock(ClientConnection.class);
        httpRequest = mock(HttpRequest.class);
        uriInfo = mock(KeycloakUriInfo.class);
        tokenManager = mock(TokenManager.class);
        formParams = new MultivaluedHashMap<>();

        when(session.getContext()).thenReturn(keycloakContext);
        when(session.users()).thenReturn(userProvider);
        when(session.sessions()).thenReturn(userSessionProvider);
        when(session.getAttributeOrDefault(anyString(), any())).thenAnswer(inv -> inv.getArgument(1));
        when(keycloakContext.getRealm()).thenReturn(realm);
        when(keycloakContext.getClient()).thenReturn(client);
        when(keycloakContext.getConnection()).thenReturn(clientConnection);
        when(keycloakContext.getHttpRequest()).thenReturn(httpRequest);
        when(keycloakContext.getUri()).thenReturn(uriInfo);

        when(client.isEnabled()).thenReturn(true);
        when(client.getClientId()).thenReturn("test-client");
        when(realm.getName()).thenReturn("test-realm");
        when(realm.getClientScopesStream()).thenReturn(Stream.empty());

        when(clientConnection.getRemoteAddr()).thenReturn("127.0.0.1");
        when(httpRequest.getUri()).thenReturn(uriInfo);
        when(uriInfo.getBaseUri()).thenReturn(URI.create("http://localhost:8080/auth/"));

        when(event.user(any(UserModel.class))).thenReturn(event);
        when(event.session(any(UserSessionModel.class))).thenReturn(event);
        when(event.detail(anyString(), anyString())).thenReturn(event);

        when(cors.add(any(Response.ResponseBuilder.class))).thenAnswer(inv -> ((Response.ResponseBuilder) inv.getArgument(0)).build());

        org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper clientConfig = org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper.fromClientModel(client);
        context = new Context(session, clientConfig, java.util.Collections.emptyMap(), formParams, event, cors, tokenManager);

        grantType = new TestableMobileNumberOTPGrantType(mockOtpUri, SHARED_SECRET, Duration.ofSeconds(5));
    }

    private static class TestableMobileNumberOTPGrantType extends MobileNumberOTPGrantType {
        public TestableMobileNumberOTPGrantType(URI otpVerifyUri, String sharedSecret, Duration requestTimeout) {
            super(otpVerifyUri, sharedSecret, requestTimeout);
        }

        @Override
        protected void checkClient() {
            // Simplified client check for unit testing
            if (client == null || !client.isEnabled()) {
                event.error(Errors.CLIENT_DISABLED);
                throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_CLIENT, "Client disabled", Response.Status.UNAUTHORIZED);
            }
        }
    }

    @ParameterizedTest
    @DisplayName("accepts valid mobile numbers and normalizes them to E.164")
    @CsvSource({
            "9876543210, IN, +919876543210",
            "9876543210, in, +919876543210",
            "+919876543210, IN, +919876543210",
            "+91 98765 43210, IN, +919876543210",
            "+91 9876543210, IN, +919876543210",
            " 9876543210 , IN, +919876543210",
    })
    void acceptsValidMobileNumberAndNormalizesToE164(String mobileNumber, String regionCode, String expected) {
        String normalized = MobileNumberOTPGrantType.validateAndNormalizeMobileNumber(mobileNumber, regionCode);
        assertThat(normalized).isEqualTo(expected);
    }

    @Test
    @DisplayName("rejects a missing region code")
    void rejectsMissingRegionCode() {
        assertThatThrownBy(() -> MobileNumberOTPGrantType.validateAndNormalizeMobileNumber("4155552671", null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Missing or Invalid region_code");
    }

    @Test
    @DisplayName("rejects a blank region code")
    void rejectsBlankRegionCode() {
        assertThatThrownBy(() -> MobileNumberOTPGrantType.validateAndNormalizeMobileNumber("4155552671", "   "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Missing or Invalid region_code");
    }

    @Test
    @DisplayName("rejects an unsupported region code")
    void rejectsUnsupportedRegionCode() {
        assertThatThrownBy(() -> MobileNumberOTPGrantType.validateAndNormalizeMobileNumber("4155552671", "ZZ"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Missing or Invalid region_code");
    }

    @Test
    @DisplayName("rejects a null mobile number")
    void rejectsNullMobileNumber() {
        assertThatThrownBy(() -> MobileNumberOTPGrantType.validateAndNormalizeMobileNumber(null, "US"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Missing mobile_number");
    }

    @Test
    @DisplayName("rejects a blank mobile number")
    void rejectsBlankMobileNumber() {
        assertThatThrownBy(() -> MobileNumberOTPGrantType.validateAndNormalizeMobileNumber("   ", "US"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Missing mobile_number");
    }

    @Test
    @DisplayName("rejects a valid toll-free number because it is not a mobile number")
    void rejectsNonMobileNumber() {
        assertThatThrownBy(() -> MobileNumberOTPGrantType.validateAndNormalizeMobileNumber("18005551234", "US"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid mobile number");
    }

    @Test
    @DisplayName("rejects a well-formed but invalid number for the region")
    void rejectsNumberInvalidForRegion() {
        assertThatThrownBy(() -> MobileNumberOTPGrantType.validateAndNormalizeMobileNumber("9999999999", "US"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid mobile number");
    }

    @Test
    @DisplayName("rejects a malformed number that cannot be parsed")
    void rejectsMalformedNumber() {
        assertThatThrownBy(() -> MobileNumberOTPGrantType.validateAndNormalizeMobileNumber("abc123", "US"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid mobile number");
    }

    @Test
    @DisplayName("rejects a number that is too short for the region")
    void rejectsTooShortNumber() {
        assertThatThrownBy(() -> MobileNumberOTPGrantType.validateAndNormalizeMobileNumber("123", "US"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid mobile number");
    }

    @Test
    @DisplayName("rejects a number that is too long for the region")
    void rejectsTooLongNumber() {
        assertThatThrownBy(
                () -> MobileNumberOTPGrantType.validateAndNormalizeMobileNumber("123456789012345678901234567890", "US"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid mobile number");
    }

    @Test
    @DisplayName("throws USER_NOT_FOUND error when user is not found by mobile number and does not create user")
    void throwsUserNotFoundWhenUserDoesNotExist() {
        formParams.add("region_code", "IN");
        formParams.add("mobile_number", "9876543210");
        formParams.add("otp", "123456");

        when(userProvider.searchForUserByUserAttributeStream(realm, "mobileNumber", "+919876543210"))
                .thenReturn(Stream.empty());

        assertThatThrownBy(() -> grantType.process(context))
                .isInstanceOf(CorsErrorResponseException.class)
                .satisfies(ex -> {
                    CorsErrorResponseException corsEx = (CorsErrorResponseException) ex;
                    assertThat(corsEx.getResponse().getStatus()).isEqualTo(Response.Status.BAD_REQUEST.getStatusCode());
                });

        verify(event).error(Errors.USER_NOT_FOUND);
        verify(userProvider, never()).addUser(any(), any());
    }

    @Test
    @DisplayName("throws USER_DISABLED error when user is disabled and does not create user")
    void throwsUserDisabledWhenUserIsDisabled() {
        formParams.add("region_code", "IN");
        formParams.add("mobile_number", "9876543210");
        formParams.add("otp", "123456");

        UserModel user = mock(UserModel.class);
        when(user.isEnabled()).thenReturn(false);

        when(userProvider.searchForUserByUserAttributeStream(realm, "mobileNumber", "+919876543210"))
                .thenReturn(Stream.of(user));

        assertThatThrownBy(() -> grantType.process(context))
                .isInstanceOf(CorsErrorResponseException.class)
                .satisfies(ex -> {
                    CorsErrorResponseException corsEx = (CorsErrorResponseException) ex;
                    assertThat(corsEx.getResponse().getStatus()).isEqualTo(Response.Status.BAD_REQUEST.getStatusCode());
                });

        verify(event).user(user);
        verify(event).error(Errors.USER_DISABLED);
        verify(userProvider, never()).addUser(any(), any());
    }

    @Test
    @DisplayName("successfully authenticates existing user by mobile number without user creation")
    void successfullyAuthenticatesExistingUser() {
        formParams.add("region_code", "IN");
        formParams.add("mobile_number", "9876543210");
        formParams.add("otp", "123456");
        formParams.add("scope", "openid");

        UserModel user = mock(UserModel.class);
        when(user.isEnabled()).thenReturn(true);
        when(user.getId()).thenReturn("user-uuid-123");
        when(user.getUsername()).thenReturn("testuser");

        when(userProvider.searchForUserByUserAttributeStream(realm, "mobileNumber", "+919876543210"))
                .thenReturn(Stream.of(user));

        UserSessionModel userSession = mock(UserSessionModel.class);
        AuthenticatedClientSessionModel clientSession = mock(AuthenticatedClientSessionModel.class);

        when(userSessionProvider.createUserSession(any(), eq(realm), eq(user), eq("testuser"),
                eq("127.0.0.1"), eq("urn:custom:mobilenumber_otp"), eq(false), any(), any(), any()))
                .thenReturn(userSession);
        when(userSessionProvider.createClientSession(realm, client, userSession))
                .thenReturn(clientSession);

        ClientScopeModel clientScope = mock(ClientScopeModel.class);
        when(client.getClientScopes(true)).thenReturn(java.util.Map.of("openid", clientScope));

        when(clientSession.getClient()).thenReturn(client);
        when(clientSession.getUserSession()).thenReturn(userSession);
        when(clientSession.getRealm()).thenReturn(realm);
        when(userSession.getRealm()).thenReturn(realm);

        TokenManager.AccessTokenResponseBuilder tokenResponseBuilder = mock(
                TokenManager.AccessTokenResponseBuilder.class,
                org.mockito.Mockito.RETURNS_SELF);
        org.keycloak.representations.AccessTokenResponse tokenResponse = new org.keycloak.representations.AccessTokenResponse();
        org.keycloak.representations.RefreshToken refreshToken = mock(org.keycloak.representations.RefreshToken.class);
        when(refreshToken.getType()).thenReturn("refresh_token");
        org.keycloak.representations.AccessToken accessToken = mock(org.keycloak.representations.AccessToken.class);
        when(accessToken.getType()).thenReturn("bearer");

        when(tokenManager.responseBuilder(any(), any(), any(), any(), any(), any()))
                .thenReturn(tokenResponseBuilder);
        when(tokenResponseBuilder.getRefreshToken()).thenReturn(refreshToken);
        when(tokenResponseBuilder.getAccessToken()).thenReturn(accessToken);
        when(tokenResponseBuilder.build()).thenReturn(tokenResponse);

        Response response = grantType.process(context);

        assertThat(response).isNotNull();
        assertThat(response.getStatus()).isEqualTo(Response.Status.OK.getStatusCode());

        verify(userSession).setNote("otp_verified", "+919876543210");
        verify(event).user(user);
        verify(event).session(userSession);
        verify(event).success();
        verify(userProvider, never()).addUser(any(), any());
    }

    @Test
    @DisplayName("rejects missing mobile number in process")
    void rejectsMissingMobileNumberInProcess() {
        formParams.add("region_code", "IN");
        formParams.add("otp", "123456");

        assertThatThrownBy(() -> grantType.process(context))
                .isInstanceOf(CorsErrorResponseException.class)
                .satisfies(ex -> {
                    CorsErrorResponseException corsEx = (CorsErrorResponseException) ex;
                    assertThat(corsEx.getResponse().getStatus()).isEqualTo(Response.Status.BAD_REQUEST.getStatusCode());
                });

        verify(event).error(Errors.INVALID_REQUEST);
    }

    @Test
    @DisplayName("rejects missing otp in process")
    void rejectsMissingOtpInProcess() {
        formParams.add("region_code", "IN");
        formParams.add("mobile_number", "9876543210");

        assertThatThrownBy(() -> grantType.process(context))
                .isInstanceOf(CorsErrorResponseException.class)
                .satisfies(ex -> {
                    CorsErrorResponseException corsEx = (CorsErrorResponseException) ex;
                    assertThat(corsEx.getResponse().getStatus()).isEqualTo(Response.Status.BAD_REQUEST.getStatusCode());
                });

        verify(event).error(Errors.INVALID_REQUEST);
    }

    @Test
    @DisplayName("rejects invalid region code in process")
    void rejectsInvalidRegionCodeInProcess() {
        formParams.add("region_code", "ZZ");
        formParams.add("mobile_number", "9876543210");
        formParams.add("otp", "123456");

        assertThatThrownBy(() -> grantType.process(context))
                .isInstanceOf(CorsErrorResponseException.class)
                .satisfies(ex -> {
                    CorsErrorResponseException corsEx = (CorsErrorResponseException) ex;
                    assertThat(corsEx.getResponse().getStatus()).isEqualTo(Response.Status.BAD_REQUEST.getStatusCode());
                });

        verify(event).error(Errors.INVALID_REQUEST);
    }

    @Test
    @DisplayName("rejects invalid mobile number format in process")
    void rejectsInvalidMobileNumberFormatInProcess() {
        formParams.add("region_code", "IN");
        formParams.add("mobile_number", "123");
        formParams.add("otp", "123456");

        assertThatThrownBy(() -> grantType.process(context))
                .isInstanceOf(CorsErrorResponseException.class)
                .satisfies(ex -> {
                    CorsErrorResponseException corsEx = (CorsErrorResponseException) ex;
                    assertThat(corsEx.getResponse().getStatus()).isEqualTo(Response.Status.BAD_REQUEST.getStatusCode());
                });

        verify(event).error(Errors.INVALID_REQUEST);
    }

    @Test
    @DisplayName("rejects invalid or expired OTP")
    void rejectsInvalidOrExpiredOtp() throws IOException {
        HttpServer rejectServer = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        rejectServer.createContext("/verify", exchange -> {
            byte[] responseBytes = "REJECTED".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, responseBytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(responseBytes);
            }
        });
        rejectServer.start();

        try {
            int port = rejectServer.getAddress().getPort();
            URI rejectUri = URI.create("http://localhost:" + port + "/verify");
            MobileNumberOTPGrantType grant = new TestableMobileNumberOTPGrantType(rejectUri, SHARED_SECRET, Duration.ofSeconds(5));

            formParams.add("region_code", "IN");
            formParams.add("mobile_number", "9876543210");
            formParams.add("otp", "999999");

            assertThatThrownBy(() -> grant.process(context))
                    .isInstanceOf(CorsErrorResponseException.class)
                    .satisfies(ex -> {
                        CorsErrorResponseException corsEx = (CorsErrorResponseException) ex;
                        assertThat(corsEx.getResponse().getStatus()).isEqualTo(Response.Status.UNAUTHORIZED.getStatusCode());
                    });

            verify(event).error(Errors.INVALID_USER_CREDENTIALS);
        } finally {
            rejectServer.stop(0);
        }
    }

    @Test
    @DisplayName("rejects disabled client")
    void rejectsDisabledClient() {
        when(client.isEnabled()).thenReturn(false);

        formParams.add("region_code", "IN");
        formParams.add("mobile_number", "9876543210");
        formParams.add("otp", "123456");

        assertThatThrownBy(() -> grantType.process(context))
                .isInstanceOf(CorsErrorResponseException.class)
                .satisfies(ex -> {
                    CorsErrorResponseException corsEx = (CorsErrorResponseException) ex;
                    assertThat(corsEx.getResponse().getStatus()).isEqualTo(Response.Status.UNAUTHORIZED.getStatusCode());
                });

        verify(event).error(Errors.CLIENT_DISABLED);
    }

    @Test
    @DisplayName("returns correct event type and empty token parameters")
    void returnsCorrectEventTypeAndTokenParameters() {
        assertThat(grantType.getEventType()).isEqualTo(org.keycloak.events.EventType.LOGIN);
        assertThat(grantType.getTokenParameterNames()).isEmpty();
    }
}
