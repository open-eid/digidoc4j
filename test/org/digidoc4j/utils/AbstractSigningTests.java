package org.digidoc4j.utils;

import org.digidoc4j.Configuration;

public abstract class AbstractSigningTests {

    protected Configuration createDigiDoc4JConfiguration() {
        Configuration result = new ConfigurationWithIpBasedAccess();
        result.setOcspSource(Configuration.TEST_OCSP_URL);
        result.setTSL(new CertificatesForTests().getTslCertificateSource());
        return result;
    }

    private static class ConfigurationWithIpBasedAccess extends Configuration {
        public ConfigurationWithIpBasedAccess() {
            super(Mode.PROD);

            getJDigiDocConfiguration().put("SIGN_OCSP_REQUESTS", Boolean.toString(false));
        }

        @Override
        public boolean hasToBeOCSPRequestSigned() {
            return false;
        }
    }
}
