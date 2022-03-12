package org.webpki.fwp_4_android;

import android.util.Log;

import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialDescriptor;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialRequestOptions;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialType;

import org.json.JSONException;
import org.webpki.util.Base64URL;

import java.io.IOException;

import java.util.ArrayList;
import java.util.List;

public class FidoSupport {
    private static final String TAG = "GAEService";

    private static final String KEY_REQUEST_CHALLENGE = "challenge";
    private static final String KEY_RP = "rp";
    private static final String KEY_RP_ID = "id";
    private static final String KEY_RP_NAME = "name";
    private static final String KEY_RP_ICON = "icon";
    private static final String KEY_USER = "user";
    private static final String KEY_USER_DISPLAY_NAME = "displayName";
    private static final String KEY_PARAMETERS = "pubKeyCredParams";
    private static final String KEY_PARAMETERS_TYPE = "type";
    private static final String KEY_TIMEOUT = "timeout";
    private static final String KEY_ATTACHMENT = "attachment";
    private static final String KEY_SESSION = "session";
    private static final String KEY_SESSION_ID = "id";
    private static final String KEY_RPID = "rpId";
    private static final String KEY_CLIENT_DATA_JSON = "clientDataJSON";
    private static final String KEY_ATTESTATION_OBJECT = "attestationObject";
    private static final String KEY_AUTHENTICATOR_DATA = "authenticatorData";
    private static final String KEY_CREDENTIAL_ID = "credentialId";
    private static final String KEY_SIGNATURE = "signature";

    public static PublicKeyCredentialRequestOptions getSignRequest(List<String> allowedKeys)
            throws IOException {
        PublicKeyCredentialRequestOptions.Builder builder =
                new PublicKeyCredentialRequestOptions.Builder();
        // signRequestContent {"challenge":"AmlL6aQKTMd24MmfZtrvBGP/oKb8+zpXRcB7bfUHrPk=",
        // "rpId":"https://webauthdemo.appspot.com",
        // "allowList":[{"type":"public-key",
        // "id":"lmKQSq81f+gLQ49jeBQNFD/3TU7R2gGFWin+zNzpDrFeWUTTkEZ7nfmIC5OWXarRNqLxImA0hE7UVOI3eeVZZg=="}],
        // "session":{"id":5704837555552256,
        // "challenge":"AmlL6aQKTMd24MmfZtrvBGP/oKb8+zpXRcB7bfUHrPk=",
        // "origin":"https://webauthdemo.appspot.com"}}

        // Parse challenge
        builder.setChallenge(new byte[]{0,1,2,3,0,1,2,3,0,1,2,3,0,1,2,3,0,1,2,3,0,1,2,3,0,1,2,3,0,1,2,3});
      //          BaseEncoding.base64().decode("22" /*signRequestJson.getString(KEY_REQUEST_CHALLENGE )*/));

        // Parse timeout
        builder.setTimeoutSeconds(120.0);

        // Parse rpId
//           String rpId = signRequestJson.getString(KEY_RPID);
        String rpId = "https://test.webpki.org";
        builder.setRpId(rpId);

        // Parse session id
//          JSONObject session = signRequestJson.getJSONObject(KEY_SESSION);
//          String sessionId = String.valueOf(session.getLong(KEY_SESSION_ID));

        // Parse allow list
        List<PublicKeyCredentialDescriptor> descriptors = new ArrayList<>();
        for (String allowedKey : allowedKeys) {
            PublicKeyCredentialDescriptor publicKeyCredentialDescriptor =
                    new PublicKeyCredentialDescriptor(
                            PublicKeyCredentialType.PUBLIC_KEY.toString(),
                            Base64URL.decode(allowedKey),
                            /* transports= */ null);
            descriptors.add(publicKeyCredentialDescriptor);
        }
        builder.setAllowList(descriptors);

        return builder.build();
    }

}
