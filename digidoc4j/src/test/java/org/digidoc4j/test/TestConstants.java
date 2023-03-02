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

}
