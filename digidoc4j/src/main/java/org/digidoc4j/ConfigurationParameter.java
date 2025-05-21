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

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */
public enum ConfigurationParameter {

  ConnectionTimeoutInMillis,
  SocketTimeoutInMillis,
  @Deprecated RevocationAndTimestampDeltaInMinutes,
  AllowedTimestampAndOCSPResponseDeltaInMinutes,
  SignatureProfile,
  SignatureDigestAlgorithm,
  DataFileDigestAlgorithm,
  ArchiveTimestampDigestAlgorithm("ARCHIVE_TIMESTAMP_DIGEST_ALGORITHM"),
  ArchiveTimestampReferenceDigestAlgorithm("ARCHIVE_TIMESTAMP_REFERENCE_DIGEST_ALGORITHM"),
  TspSource,
  TspSourceForArchiveTimestamps("TSP_SOURCE_FOR_ARCHIVE_TIMESTAMPS"),
  LotlLocation("LOTL_LOCATION"),
  LotlTruststorePath("LOTL_TRUSTSTORE_PATH"),
  LotlTruststoreType("LOTL_TRUSTSTORE_TYPE"),
  LotlTruststorePassword("LOTL_TRUSTSTORE_PASSWORD"),
  LotlPivotSupportEnabled("LOTL_PIVOT_SUPPORT_ENABLED"),
  TslCacheExpirationTimeInMillis,
  ValidationPolicy,
  OcspSource,
  OcspAccessCertificateFile,
  OcspAccessCertificatePassword,
  AllowedOcspRespondersForTM,
  HttpProxyHost("HTTP_PROXY_HOST"),
  HttpProxyPort("HTTP_PROXY_PORT"),
  HttpProxyUser("HTTP_PROXY_USER"),
  HttpProxyPassword("HTTP_PROXY_PASSWORD"),
  HttpsProxyHost("HTTPS_PROXY_HOST"),
  HttpsProxyPort("HTTPS_PROXY_PORT"),
  HttpsProxyUser("HTTPS_PROXY_USER"),
  HttpsProxyPassword("HTTPS_PROXY_PASSWORD"),
  SslKeystoreType("SSL_KEYSTORE_TYPE"),
  SslTruststoreType("SSL_TRUSTSTORE_TYPE"),
  SslKeystorePath("SSL_KEYSTORE_PATH"),
  SslKeystorePassword("SSL_KEYSTORE_PASSWORD"),
  SslTruststorePath("SSL_TRUSTSTORE_PATH"),
  SslTruststorePassword("SSL_TRUSTSTORE_PASSWORD"),
  SslProtocol("SSL_PROTOCOL"),
  SupportedSslProtocols("SUPPORTED_SSL_PROTOCOLS"),
  SupportedSslCipherSuites("SUPPORTED_SSL_CIPHER_SUITES"),
  SignOcspRequests,
  TspsCount,
  TspCountrySource,
  TspCountryKeystorePath,
  TspCountryKeystoreType,
  TspCountryKeystorePassword,
  preferAiaOcsp,
  aiaOcspsCount,
  issuerCn,
  aiaOcspSource,
  useNonce,
  AllowASN1UnsafeInteger,
  PrintValidationReport,
  @Deprecated IsFullSimpleReportNeeded,

  TslHttpProxyHost("TSL_HTTP_PROXY_HOST"),
  TslHttpProxyPort("TSL_HTTP_PROXY_PORT"),
  TslHttpProxyUser("TSL_HTTP_PROXY_USER"),
  TslHttpProxyPassword("TSL_HTTP_PROXY_PASSWORD"),
  TslHttpsProxyHost("TSL_HTTPS_PROXY_HOST"),
  TslHttpsProxyPort("TSL_HTTPS_PROXY_PORT"),
  TslHttpsProxyUser("TSL_HTTPS_PROXY_USER"),
  TslHttpsProxyPassword("TSL_HTTPS_PROXY_PASSWORD"),
  TslSslKeystoreType("TSL_SSL_KEYSTORE_TYPE"),
  TslSslTruststoreType("TSL_SSL_TRUSTSTORE_TYPE"),
  TslSslKeystorePath("TSL_SSL_KEYSTORE_PATH"),
  TslSslKeystorePassword("TSL_SSL_KEYSTORE_PASSWORD"),
  TslSslTruststorePath("TSL_SSL_TRUSTSTORE_PATH"),
  TslSslTruststorePassword("TSL_SSL_TRUSTSTORE_PASSWORD"),
  TslSslProtocol("TSL_SSL_PROTOCOL"),
  TslSupportedSslProtocols("TSL_SUPPORTED_SSL_PROTOCOLS"),
  TslSupportedSslCipherSuites("TSL_SUPPORTED_SSL_CIPHER_SUITES"),

  OcspHttpProxyHost("OCSP_HTTP_PROXY_HOST"),
  OcspHttpProxyPort("OCSP_HTTP_PROXY_PORT"),
  OcspHttpProxyUser("OCSP_HTTP_PROXY_USER"),
  OcspHttpProxyPassword("OCSP_HTTP_PROXY_PASSWORD"),
  OcspHttpsProxyHost("OCSP_HTTPS_PROXY_HOST"),
  OcspHttpsProxyPort("OCSP_HTTPS_PROXY_PORT"),
  OcspHttpsProxyUser("OCSP_HTTPS_PROXY_USER"),
  OcspHttpsProxyPassword("OCSP_HTTPS_PROXY_PASSWORD"),
  OcspSslKeystoreType("OCSP_SSL_KEYSTORE_TYPE"),
  OcspSslTruststoreType("OCSP_SSL_TRUSTSTORE_TYPE"),
  OcspSslKeystorePath("OCSP_SSL_KEYSTORE_PATH"),
  OcspSslKeystorePassword("OCSP_SSL_KEYSTORE_PASSWORD"),
  OcspSslTruststorePath("OCSP_SSL_TRUSTSTORE_PATH"),
  OcspSslTruststorePassword("OCSP_SSL_TRUSTSTORE_PASSWORD"),
  OcspSslProtocol("OCSP_SSL_PROTOCOL"),
  OcspSupportedSslProtocols("OCSP_SUPPORTED_SSL_PROTOCOLS"),
  OcspSupportedSslCipherSuites("OCSP_SUPPORTED_SSL_CIPHER_SUITES"),

  TspHttpProxyHost("TSP_HTTP_PROXY_HOST"),
  TspHttpProxyPort("TSP_HTTP_PROXY_PORT"),
  TspHttpProxyUser("TSP_HTTP_PROXY_USER"),
  TspHttpProxyPassword("TSP_HTTP_PROXY_PASSWORD"),
  TspHttpsProxyHost("TSP_HTTPS_PROXY_HOST"),
  TspHttpsProxyPort("TSP_HTTPS_PROXY_PORT"),
  TspHttpsProxyUser("TSP_HTTPS_PROXY_USER"),
  TspHttpsProxyPassword("TSP_HTTPS_PROXY_PASSWORD"),
  TspSslKeystoreType("TSP_SSL_KEYSTORE_TYPE"),
  TspSslTruststoreType("TSP_SSL_TRUSTSTORE_TYPE"),
  TspSslKeystorePath("TSP_SSL_KEYSTORE_PATH"),
  TspSslKeystorePassword("TSP_SSL_KEYSTORE_PASSWORD"),
  TspSslTruststorePath("TSP_SSL_TRUSTSTORE_PATH"),
  TspSslTruststorePassword("TSP_SSL_TRUSTSTORE_PASSWORD"),
  TspSslProtocol("TSP_SSL_PROTOCOL"),
  TspSupportedSslProtocols("TSP_SUPPORTED_SSL_PROTOCOLS"),
  TspSupportedSslCipherSuites("TSP_SUPPORTED_SSL_CIPHER_SUITES"),

  TempFileMaxAgeInMillis,
  MaxAllowedZipCompressionRatio,
  ZipCompressionRatioCheckThreshold;


  final String fileKey;

  ConfigurationParameter() {
    this.fileKey = null;
  }

  ConfigurationParameter(String fileKey) {
    this.fileKey = fileKey;
  }
}
