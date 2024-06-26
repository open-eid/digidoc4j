/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Constants holder for system property names, default and environmental values. There is dedicated constant class for
 * DDoc4J properties and parameters to keep integration as apart as possible
 *
 * @author Janar Rahumeel (CGI Estonia)
 */

public final class Constant {

  public static final int ONE_SECOND_IN_MILLISECONDS = 1000;
  public static final int ONE_MINUTE_IN_MILLISECONDS = 60000;
  public static final int ONE_DAY_IN_MINUTES = 24 * 60;
  public static final long ONE_DAY_IN_MILLISECONDS = 1000 * 60 * 60 * 24;
  public static final long ONE_MB_IN_BYTES = 1048576;
  public static final long CACHE_ALL_DATA_FILES = -1;
  public static final long CACHE_NO_DATA_FILES = 0;

  public static final String DDOC_CONTAINER_TYPE = "DDOC";
  public static final String BDOC_CONTAINER_TYPE = "BDOC";
  public static final String ASICE_CONTAINER_TYPE = "ASICE";
  public static final String ASICS_CONTAINER_TYPE = "ASICS";
  public static final String PADES_CONTAINER_TYPE = "PADES";

  public static final String USER_AGENT_STRING = "LIB DigiDoc4j";

  public static class System {

    public static final String JAVAX_NET_SSL_TRUST_STORE_PASSWORD = "javax.net.ssl.trustStorePassword";
    public static final String JAVAX_NET_SSL_TRUST_STORE = "javax.net.ssl.trustStore";
    public static final String JAVAX_NET_SSL_KEY_STORE_PASSWORD = "javax.net.ssl.keyStorePassword";
    public static final String JAVAX_NET_SSL_KEY_STORE = "javax.net.ssl.keyStore";
    public static final String HTTPS_PROXY_PORT = "https.proxyPort";
    public static final String HTTPS_PROXY_HOST = "https.proxyHost";
    public static final String HTTP_PROXY_PORT = "http.proxyPort";
    public static final String HTTP_PROXY_HOST = "http.proxyHost";
    public static final String ORG_BOUNCYCASTLE_ASN1_ALLOW_UNSAFE_INTEGER = "org.bouncycastle.asn1.allow_unsafe_integer";
  }

  public static class Default {

    public static final SignatureProfile SIGNATURE_PROFILE = SignatureProfile.LT;
    public static final DigestAlgorithm SIGNATURE_DIGEST_ALGORITHM = DigestAlgorithm.SHA256;
    public static final DigestAlgorithm DATAFILE_DIGEST_ALGORITHM = DigestAlgorithm.SHA256;
    public static final DigestAlgorithm ARCHIVE_TIMESTAMP_DIGEST_ALGORITHM = DigestAlgorithm.SHA512;
    public static final String FULL_SIMPLE_REPORT = "false";
  }

  public static class Test {

    public static final String TSP_SOURCE = "http://tsa.demo.sk.ee/tsa";
    public static final String LOTL_LOCATION = "https://open-eid.github.io/test-TL/tl-mp-test-EE.xml";
    public static final String LOTL_TRUSTSTORE_PATH = "classpath:truststores/test-lotl-truststore.p12";
    public static final String VALIDATION_POLICY = "conf/test_constraint.xml";
    public static final String OCSP_SOURCE = "http://demo.sk.ee/ocsp";
    public static final String[] DEFAULT_OCSP_RESPONDERS = {"TEST of SK OCSP RESPONDER 2020", "TEST of EID-SK 2016 OCSP RESPONDER 2018", "TEST of SK OCSP RESPONDER 2011",
            "TEST-SK OCSP RESPONDER 2005", "TEST-SK OCSP RESPONDER", "SK OCSP RESPONDER 2011", "ESTEID-SK 2007 OCSP RESPONDER 2010",
            "ESTEID-SK 2007 OCSP RESPONDER", "ESTEID-SK OCSP RESPONDER 2005", "ESTEID-SK OCSP RESPONDER", "EID-SK 2007 OCSP RESPONDER 2010",
            "EID-SK 2007 OCSP RESPONDER", "EID-SK OCSP RESPONDER", "KLASS3-SK 2010 OCSP RESPONDER", "KLASS3-SK OCSP RESPONDER 2009", "KLASS3-SK OCSP RESPONDER"
    };

  }

  public static class Production {

    public static final String TSP_SOURCE = "http://tsa.sk.ee";
    public static final String LOTL_LOCATION = "https://ec.europa.eu/tools/lotl/eu-lotl.xml";
    public static final String LOTL_TRUSTSTORE_PATH = "classpath:truststores/lotl-truststore.p12";
    public static final String VALIDATION_POLICY = "conf/constraint.xml";
    public static final String OCSP_SOURCE = "http://ocsp.sk.ee/";
    public static final List<String> DEFAULT_REQUIRED_TERRITORIES = Collections.singletonList("EE");
    public static final List<String> DEFAULT_TRUSTED_TERRITORIES = Collections.unmodifiableList(
      Arrays.asList("AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FR",
        "EL", "HU", "HR", "IE", "IS", "IT", "LT", "LU", "LV", "LI", "MT", "NO", "NL",
        "PL", "PT", "RO", "SE", "SI", "SK", "UK"));
    public static final String[] DEFAULT_OCSP_RESPONDERS = {"SK OCSP RESPONDER 2011", "ESTEID-SK 2007 OCSP RESPONDER 2010",
            "ESTEID-SK 2007 OCSP RESPONDER", "ESTEID-SK OCSP RESPONDER 2005", "ESTEID-SK OCSP RESPONDER", "EID-SK 2007 OCSP RESPONDER 2010",
            "EID-SK 2007 OCSP RESPONDER", "EID-SK OCSP RESPONDER", "KLASS3-SK 2010 OCSP RESPONDER", "KLASS3-SK OCSP RESPONDER 2009", "KLASS3-SK OCSP RESPONDER"
    };

  }

  public static class DDoc4J {

    public static final String OCSP_PKCS_12_CONTAINER = "DIGIDOC_PKCS12_CONTAINER";
    public static final String OCSP_PKCS_12_PASSWORD = "DIGIDOC_PKCS12_PASSWD";
    public static final String OCSP_SIGN_REQUESTS = "SIGN_OCSP_REQUESTS";
    public static final String SECURITY_PROVIDER = "org.bouncycastle.jce.provider.BouncyCastleProvider";
    public static final String SECURITY_PROVIDER_NAME = "BC";
    public static final String CANONICALIZATION_FACTORY_IMPLEMENTATION = "org.digidoc4j.ddoc.c14n.TinyXMLCanonicalizer";
    public static final String NOTARY_IMPLEMENTATION = "org.digidoc4j.ddoc.factory.BouncyCastleNotaryFactory";
    public static final String TSL_FACTORY_IMPLEMENTATION = "org.digidoc4j.ddoc.tsl.DigiDocTrustServiceFactory";
    public static final String FACTORY_IMPLEMENTATION = "org.digidoc4j.ddoc.factory.SAXDigiDocFactory";
    public static final String MAX_DATAFILE_CACHED = "-1";
    public static final String USE_LOCAL_TSL = "true";
    public static final String KEY_USAGE_CHECK = "false";

  }

}
