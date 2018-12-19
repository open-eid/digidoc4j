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
  HttpProxyHost,
  HttpProxyPort,
  HttpsProxyHost,
  HttpsProxyPort,
  HttpProxyUser,
  HttpProxyPassword,
  SslKeystoreType,
  SslTruststoreType,
  SslKeystorePath,
  SslKeystorePassword,
  SslTruststorePath,
  SslTruststorePassword,
  SignOcspRequests,
  TspsCount,
  TspCountrySource,
  TspCountryKeystorePath,
  TspCountryKeystoreType,
  TspCountryKeystorePassword,
  AllowASN1UnsafeInteger,
  PrintValidationReport,
  IsFullSimpleReportNeeded
}
