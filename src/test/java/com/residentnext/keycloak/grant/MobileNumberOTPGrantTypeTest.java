package com.residentnext.keycloak.grant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class MobileNumberOTPGrantTypeTest {

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
}
