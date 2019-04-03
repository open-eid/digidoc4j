package org.digidoc4j;

import java.util.Arrays;
import java.util.List;

public class SignatureContainerMatcherValidator {

    private static final List<SignatureProfile> BDOC_ONLY_SIGNATURE_PROFILES = Arrays.asList(SignatureProfile.LT_TM, SignatureProfile.B_EPES);

    public static boolean isBDocOnlySignature(SignatureProfile signatureProfile) {
        if (signatureProfile == null) {
            return false;
        }
        return BDOC_ONLY_SIGNATURE_PROFILES.contains(signatureProfile);
    }
}
