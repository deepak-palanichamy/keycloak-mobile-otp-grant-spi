package com.gatehub.keycloak.grant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.Config.Scope;

class MobileNumberOTPGrantTypeFactoryTest {

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = { "", "  ", "abc", "0", "-5" })
    void parseTimeoutSecondsFallsBackToDefaultForMissingOrInvalidValues(String value) {
        assertThat(MobileNumberOTPGrantTypeFactory.parseTimeoutSeconds(value))
                .isEqualTo(MobileNumberOTPGrantTypeFactory.DEFAULT_REQUEST_TIMEOUT_INSEC);
    }

    @Test
    void parseTimeoutSecondsUsesConfiguredPositiveValue() {
        assertThat(MobileNumberOTPGrantTypeFactory.parseTimeoutSeconds(" 12 ")).isEqualTo(12);
    }

    @Test
    void initSucceedsWhenTimeoutIsNotConfigured() {
        Scope config = mock(Scope.class);
        when(config.get(eq("validation-url"), any())).thenReturn("https://otp.example.com/verify");
        when(config.get(eq("shared-secret"), any())).thenReturn("secret");
        when(config.get(eq("timeout-seconds"), any())).thenReturn(null);

        MobileNumberOTPGrantTypeFactory factory = new MobileNumberOTPGrantTypeFactory();
        factory.init(config);

        assertThat(factory.create(null)).isInstanceOf(MobileNumberOTPGrantType.class);
    }

    @Test
    void initRejectsNonHttpsValidationUrl() {
        Scope config = mock(Scope.class);
        when(config.get(eq("validation-url"), any())).thenReturn("http://otp.example.com/verify");
        when(config.get(eq("shared-secret"), any())).thenReturn("secret");

        assertThatThrownBy(() -> new MobileNumberOTPGrantTypeFactory().init(config))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("HTTPS");
    }
}
