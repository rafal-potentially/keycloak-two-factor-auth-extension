package org.prg.twofactorauth.rest;

import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.OTPPolicy;
import org.keycloak.models.utils.TimeBasedOTP;
import org.prg.twofactorauth.dto.TwoFactorAuthSecretData;
import org.prg.twofactorauth.dto.TwoFactorAuthSubmission;
import org.prg.twofactorauth.dto.TwoFactorAuthVerificationData;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.utils.Base32;
import org.keycloak.models.utils.HmacOTP;
import org.keycloak.utils.CredentialHelper;
import org.keycloak.utils.TotpUtils;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class User2FAResource {

	private final KeycloakSession session;
    private final UserModel user;

    public final int TotpSecretLength = 20;
	
	public User2FAResource(KeycloakSession session, UserModel user) {
		this.session = session;
        this.user = user;
	}

    @GET
    @Path("generate-2fa")
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response generate2FA() {
        final RealmModel realm = this.session.getContext().getRealm();
        final String totpSecret = HmacOTP.generateSecret(TotpSecretLength);
        final String totpSecretQrCode = TotpUtils.qrCode(totpSecret, realm, user);
        final String totpSecretEncoded = Base32.encode(totpSecret.getBytes());
        return Response.ok(new TwoFactorAuthSecretData(totpSecretEncoded, totpSecretQrCode)).build();
    }

    @POST
    @NoCache
    @Path("validate-2fa-code")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response validate2FACode(final TwoFactorAuthVerificationData submission) {
        if (!submission.isValid()) {
            throw new BadRequestException("one or more data field for otp validation are blank");
        }

        final RealmModel realm = this.session.getContext().getRealm();
        final CredentialModel credentialModel = session.userCredentialManager().getStoredCredentialByNameAndType(realm, user, submission.getDeviceName(), OTPCredentialModel.TYPE);
        if (credentialModel == null) {
            throw new BadRequestException("device not found");
        }
        boolean isCredentialsValid;
        try {
            var otpCredentialProvider = session.getProvider(CredentialProvider.class, "keycloak-otp");
            final OTPCredentialModel otpCredentialModel = OTPCredentialModel.createFromCredentialModel(credentialModel);
            final String credentialId = otpCredentialModel.getId();
            isCredentialsValid = session.userCredentialManager().isValid(realm, user, new UserCredentialModel(credentialId, otpCredentialProvider.getType(), submission.getTotpCode()));
        } catch (RuntimeException e) {
            e.printStackTrace();
            throw new InternalServerErrorException("internal error");
        }

        if (!isCredentialsValid) {
            throw new BadRequestException("invalid totp code");
        }

        return Response.noContent().build();
    }

    @POST
    @NoCache
    @Path("submit-2fa")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response register2FA(final TwoFactorAuthSubmission submission) {
        if (!submission.isValid()) {
            throw new BadRequestException("one or more data field for otp registration are blank");
        }

        final String encodedTotpSecret = submission.getEncodedTotpSecret();
        final String totpSecret = new String(Base32.decode(encodedTotpSecret));
        if (totpSecret.length() < TotpSecretLength) {
            throw new BadRequestException("totp secret is invalid");
        }

        final RealmModel realm = this.session.getContext().getRealm();
        final CredentialModel credentialModel = session.userCredentialManager().getStoredCredentialByNameAndType(realm, user, submission.getDeviceName(), OTPCredentialModel.TYPE);
        if (credentialModel != null && !submission.isOverwrite()) {
            throw new ForbiddenException("2FA is already configured for device: " + submission.getDeviceName());
        }

        final OTPCredentialModel otpCredentialModel = OTPCredentialModel.createFromPolicy(realm, totpSecret, submission.getDeviceName());
        if (!CredentialHelper.createOTPCredential(this.session, realm, user, submission.getTotpInitialCode(), otpCredentialModel)) {
            throw new BadRequestException("otp registration data is invalid");
        }

        return Response.noContent().build();
    }

    @POST
    @NoCache
    @Path("disable-totp")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response disableTotpWithValidation(final TwoFactorAuthVerificationData data) {
        try {
            if (data == null || data.getTotpCode() == null || data.getTotpCode().isEmpty()) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(createErrorResponse("Invalid TOTP code", CODE_INVALID_CODE))
                        .build();
            }

            List<CredentialModel> totpCredentials = user.credentialManager()
                    .getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE)
                    .collect(Collectors.toList());

            if (totpCredentials.isEmpty()) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(createErrorResponse("TOTP is not enabled", CODE_TOTP_NOT_ENABLED))
                        .build();
            }

            final RealmModel realm = session.getContext().getRealm();

            TimeBasedOTP timeBasedOTP = new TimeBasedOTP(
                    realm.getOTPPolicy().getAlgorithm(),
                    realm.getOTPPolicy().getDigits(),
                    realm.getOTPPolicy().getPeriod(),
                    0);

            boolean validCode = false;
            for (CredentialModel credModel : totpCredentials) {
                OTPCredentialModel otpCredential = OTPCredentialModel.createFromCredentialModel(credModel);

                try {
                    String secretData = otpCredential.getSecretData();

                    try {
                        JsonObject jsonData = JsonParser.parseString(secretData).getAsJsonObject();
                        String secret = jsonData.get("value").getAsString();
                        byte[] decodedSecret = Base32.decode(secret);

                        if (timeBasedOTP.validateTOTP(data.getTotpCode(), decodedSecret)) {
                            validCode = true;
                            break;
                        }
                    } catch (Exception e) {
                        System.out.println("JSON parsing failed, trying alternative method");
                    }

                    if (!validCode && timeBasedOTP.validateTOTP(data.getTotpCode(), secretData.getBytes())) {
                        validCode = true;
                        break;
                    }

                    try {
                        String otpSecretData = otpCredential.getOTPSecretData().getValue();
                        if (!validCode && timeBasedOTP.validateTOTP(data.getTotpCode(),
                                otpSecretData != null ? otpSecretData.getBytes() : new byte[0])) {
                            validCode = true;
                            break;
                        }
                    } catch (Exception e) {
                    }

                } catch (Exception e) {
                    e.printStackTrace();
                    continue;
                }
            }

            if (!validCode) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(createErrorResponse("Invalid TOTP code", CODE_INVALID_TOTP))
                        .build();
            }

            for (CredentialModel cred : totpCredentials) {
                try {
                    user.credentialManager().removeStoredCredentialById(cred.getId());
                } catch (Exception e) {
                    return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                            .entity(createErrorResponse("Failed to disable TOTP", CODE_OPERATION_FAILED))
                            .build();
                }
            }

            return Response.ok(new HashMap<String, Object>() {{
                put("message", "TOTP validated and disabled successfully");
                put("enabled", false);
                put("userId", user.getId());
                put("code", CODE_SUCCESS);
            }}).build();

        } catch (Exception e) {
            e.printStackTrace();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(createErrorResponse("Server error while disabling TOTP", CODE_SERVER_ERROR))
                    .build();
        }
    }

    private Map<String, Object> createErrorResponse(String message, int code) {
        return new HashMap<String, Object>() {{
            put("error", message);
            put("code", code);
        }};
    }

    private boolean isTotpEnabled() {
        return user.credentialManager()
                .getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE)
                .findAny()
                .isPresent();
    }

    private static final int CODE_SUCCESS = 0;
    private static final int CODE_INVALID_USER_ID = 1;
    private static final int CODE_INVALID_CODE = 2;
    private static final int CODE_TOTP_NOT_ENABLED = 3;
    private static final int CODE_TOTP_ALREADY_ENABLED = 4;
    private static final int CODE_SERVER_ERROR = 5;
    private static final int CODE_TOTP_SETUP_REQUIRED = 6;
    private static final int CODE_INVALID_TOTP = 7;
    private static final int CODE_OPERATION_FAILED = 8;
    private static final int CODE_UNAUTHORIZED = 9;
    private static final int CODE_FORBIDDEN = 10;
}
