package org.digidoc4j.test.util;

import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.Container;
import org.digidoc4j.Signature;
import org.junit.Assert;

import java.util.regex.Pattern;

public final class TestIdUtil {

    public static final String SIGNATURE_ID_REGEX = "^S-[0-9A-Z]{64}$";
    public static final Pattern SIGNATURE_ID_PATTERN = Pattern.compile(SIGNATURE_ID_REGEX);

    public static final String CERTIFICATE_ID_REGEX = "^C-[0-9A-Z]{64}$";
    public static final Pattern CERTIFICATE_ID_PATTERN = Pattern.compile(CERTIFICATE_ID_REGEX);


    public static boolean matchesSignatureIdPattern(String id) {
        return StringUtils.isNotBlank(id) && SIGNATURE_ID_PATTERN.matcher(id).matches();
    }

    public static void assertMatchesSignatureIdPattern(String id) {
        Assert.assertNotNull("Signature ID must not be null");
        Assert.assertTrue("Signature ID must match \"" + SIGNATURE_ID_REGEX + "\", actual value was " + id,
                SIGNATURE_ID_PATTERN.matcher(id).matches());
    }

    public static Signature findExactlyOneSignatureByXmlDigitalSignatureId(Container container, String xmlDigitalSignatureId) {
        return container.getSignatures().stream()
                .filter(s -> xmlDigitalSignatureId.equals(s.getId()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("No signature " + xmlDigitalSignatureId + " found"));
    }


    public static boolean matchesCertificateIdPattern(String id) {
        return StringUtils.isNotBlank(id) && CERTIFICATE_ID_PATTERN.matcher(id).matches();
    }

    public static void assertMatchesCertificateIdPattern(String id) {
        Assert.assertNotNull("Certificate ID must not be null");
        Assert.assertTrue("Certificate ID must match \"" + CERTIFICATE_ID_REGEX + "\", actual value was " + id,
                CERTIFICATE_ID_PATTERN.matcher(id).matches());
    }


    private TestIdUtil() {
    }
}
