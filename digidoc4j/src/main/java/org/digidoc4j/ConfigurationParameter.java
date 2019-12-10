package org.digidoc4j;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */
public enum ConfigurationParameter {

  ConnectionTimeoutInMillis,
  SocketTimeoutInMillis,
  TslCacheExpirationTimeInMillis,
  TslKeyStorePassword,
  RevocationAndTimestampDeltaInMinutes,
  AllowedTimestampAndOCSPResponseDeltaInMinutes,
  SignatureProfile,
  SignatureDigestAlgorithm,
  TspSource,
  TslLocation,
  TslKeyStoreLocation,
  ValidationPolicy,
  OcspSource,
  OcspAccessCertificateFile,
  OcspAccessCertificatePassword,
  AllowedOcspRespondersForTM,
  HttpProxyHost("HTTP_PROXY_HOST"),
  HttpProxyPort("HTTP_PROXY_PORT"),
  HttpsProxyHost("HTTPS_PROXY_HOST"),
  HttpsProxyPort("HTTPS_PROXY_PORT"),
  HttpProxyUser("HTTP_PROXY_USER"),
  HttpProxyPassword("HTTP_PROXY_PASSWORD"),
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
  IsFullSimpleReportNeeded,

  TslHttpProxyHost("TSL_HTTP_PROXY_HOST"),
  TslHttpProxyPort("TSL_HTTP_PROXY_PORT"),
  TslHttpsProxyHost("TSL_HTTPS_PROXY_HOST"),
  TslHttpsProxyPort("TSL_HTTPS_PROXY_PORT"),
  TslHttpProxyUser("TSL_HTTP_PROXY_USER"),
  TslHttpProxyPassword("TSL_HTTP_PROXY_PASSWORD"),
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
  OcspHttpsProxyHost("OCSP_HTTPS_PROXY_HOST"),
  OcspHttpsProxyPort("OCSP_HTTPS_PROXY_PORT"),
  OcspHttpProxyUser("OCSP_HTTP_PROXY_USER"),
  OcspHttpProxyPassword("OCSP_HTTP_PROXY_PASSWORD"),
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
  TspHttpsProxyHost("TSP_HTTPS_PROXY_HOST"),
  TspHttpsProxyPort("TSP_HTTPS_PROXY_PORT"),
  TspHttpProxyUser("TSP_HTTP_PROXY_USER"),
  TspHttpProxyPassword("TSP_HTTP_PROXY_PASSWORD"),
  TspSslKeystoreType("TSP_SSL_KEYSTORE_TYPE"),
  TspSslTruststoreType("TSP_SSL_TRUSTSTORE_TYPE"),
  TspSslKeystorePath("TSP_SSL_KEYSTORE_PATH"),
  TspSslKeystorePassword("TSP_SSL_KEYSTORE_PASSWORD"),
  TspSslTruststorePath("TSP_SSL_TRUSTSTORE_PATH"),
  TspSslTruststorePassword("TSP_SSL_TRUSTSTORE_PASSWORD"),
  TspSslProtocol("TSP_SSL_PROTOCOL"),
  TspSupportedSslProtocols("TSP_SUPPORTED_SSL_PROTOCOLS"),
  TspSupportedSslCipherSuites("TSP_SUPPORTED_SSL_CIPHER_SUITES");

  final String fileKey;

  ConfigurationParameter() {
    this.fileKey = null;
  }

  ConfigurationParameter(String fileKey) {
    this.fileKey = fileKey;
  }
}
