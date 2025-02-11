/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public final class TestConstants {

  public static final int ONE_DAY_IN_MILLIS = 1000 * 60 * 60 * 24;

  public static final String DEFAULT_TLS_PROTOCOL = "TLSv1.3";
  public static final List<String> DEFAULT_SUPPORTED_TLS_PROTOCOLS = Collections
          .unmodifiableList(Arrays.asList("TLSv1.3", "TLSv1.2"));
  public static final List<String> DEFAULT_SUPPORTED_TLS_CIPHER_SUITES = Collections
          .unmodifiableList(Arrays.asList(
                  // TLSv1.3 cipher suites
                  "TLS_AES_128_GCM_SHA256",
                  "TLS_AES_256_GCM_SHA384",
                  // TLSv1.2 cipher suites
                  "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                  "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                  "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                  "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
          ));

  // CN of specific timestamp providers
  public static final String DEMO_SK_TSA_2014_CN = "DEMO of SK TSA 2014";
  public static final String DEMO_SK_TSA_2023E_CN = "DEMO SK TIMESTAMPING AUTHORITY 2023E";
  public static final String DEMO_SK_TSA_2023R_CN = "DEMO SK TIMESTAMPING AUTHORITY 2023R";
  public static final String DEMO_SK_TSA_2025E_CN = "DEMO SK TIMESTAMPING UNIT 2025E";
  public static final String DEMO_SK_TSA_2025R_CN = "DEMO SK TIMESTAMPING UNIT 2025R";
  public static final String SK_TSA_CN = "SK TIMESTAMPING AUTHORITY";
  public static final String SK_TSA_2024E_CN = "SK TIMESTAMPING UNIT 2024E";

  // URLs of currently active timestamp providers
  public static final String DEMO_TSA_ECC_URL = "http://tsa.demo.sk.ee/tsaecc";
  public static final String DEMO_TSA_RSA_URL = "http://tsa.demo.sk.ee/tsarsa";

  // CN of currently active timestamp providers
  public static final String DEMO_TSA_ECC_CN = DEMO_SK_TSA_2025E_CN;
  public static final String DEMO_TSA_RSA_CN = DEMO_SK_TSA_2025R_CN;
  public static final String DEMO_TSA_CN = DEMO_TSA_ECC_CN;

  private TestConstants() {
  }

}
