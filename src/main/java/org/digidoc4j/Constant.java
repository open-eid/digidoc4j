package org.digidoc4j;

import java.util.Arrays;
import java.util.List;

/**
 * Constants holder for system property names, default and environmental values. There is dedicated constant class for
 * JDigiDoc properties and parameters to keep integration as apart as possible
 *
 * @author Janar Rahumeel (CGI Estonia)
 */

public final class Constant {

  public static final int ONE_SECOND_IN_MILLISECONDS = 1000;
  public static final int ONE_DAY_IN_MINUTES = 24 * 60;
  public static final long ONE_DAY_IN_MILLISECONDS = 1000 * 60 * 60 * 24;
  public static final long ONE_MB_IN_BYTES = 1048576;
  public static final long CACHE_ALL_DATA_FILES = -1;
  public static final long CACHE_NO_DATA_FILES = 0;

  @Deprecated
  public static final String BDOC_CONTAINER_TYPE = "BDOC";
  @Deprecated
  public static final String DDOC_CONTAINER_TYPE = "DDOC";
  @Deprecated
  public static final String ASICE_CONTAINER_TYPE = "ASICE";
  @Deprecated
  public static final String ASICS_CONTAINER_TYPE = "ASICS";
  @Deprecated
  public static final String PADES_CONTAINER_TYPE = "PADES";

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

    public static final String SIGNATURE_PROFILE = "LT";
    public static final String SIGNATURE_DIGEST_ALGORITHM = "SHA256";
    public static final String FULL_SIMPLE_REPORT = "false";
  }

  public static class Test {

    public static final String TSP_SOURCE = "http://demo.sk.ee/tsa";
    public static final String TSL_LOCATION = "https://open-eid.github.io/test-TL/tl-mp-test-EE.xml";
    public static final String TSL_KEYSTORE_LOCATION = "keystore/test-keystore.jks";
    public static final String VALIDATION_POLICY = "conf/test_constraint.xml";
    public static final String OCSP_SOURCE = "http://demo.sk.ee/ocsp";

  }

  public static class Production {

    public static final String TSP_SOURCE = "http://tsa.sk.ee";
    public static final String TSL_LOCATION = "https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml";
    public static final String TSL_KEYSTORE_LOCATION = "keystore/keystore.jks";
    public static final String VALIDATION_POLICY = "conf/constraint.xml";
    public static final String OCSP_SOURCE = "http://ocsp.sk.ee/";
    public static final List<String> DEFAULT_TRUESTED_TERRITORIES =
      Arrays.asList("AT", "BE", "BG", "CY", "CZ", /*"DE",*/ "DK", "EE", "ES", "FI", "FR",
        "GR", "HU", /*"HR",*/ "IE", "IS", "IT", "LT", "LU", "LV", "LI", "MT", "NO", "NL",
        "PL", "PT", "RO", "SE", "SI", "SK", "UK");

  }

  public static class JDigiDoc {

    public static final String OCSP_PKCS_12_CONTAINER = "DIGIDOC_PKCS12_CONTAINER";
    public static final String OCSP_PKCS_12_PASSWORD = "DIGIDOC_PKCS12_PASSWD";
    public static final String OCSP_SIGN_REQUESTS = "SIGN_OCSP_REQUESTS";
    public static final String SECURITY_PROVIDER = "org.bouncycastle.jce.provider.BouncyCastleProvider";
    public static final String SECURITY_PROVIDER_NAME = "BC";
    public static final String CANONICALIZATION_FACTORY_IMPLEMENTATION = "ee.sk.digidoc.c14n.TinyXMLCanonicalizer";
    public static final String NOTARY_IMPLEMENTATION = "ee.sk.digidoc.factory.BouncyCastleNotaryFactory";
    public static final String TSL_FACTORY_IMPLEMENTATION = "ee.sk.digidoc.tsl.DigiDocTrustServiceFactory";
    public static final String FACTORY_IMPLEMENTATION = "ee.sk.digidoc.factory.SAXDigiDocFactory";
    public static final String MAX_DATAFILE_CACHED = "-1";
    public static final String USE_LOCAL_TSL = "true";
    public static final String KEY_USAGE_CHECK = "false";

  }

}
