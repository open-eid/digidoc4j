package org.digidoc4j.utils;

import eu.europa.esig.dss.model.CommonDocument;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.TemporalAmount;
import java.util.Enumeration;
import java.util.Objects;

/**
 * An implementation of {@link eu.europa.esig.dss.model.DSSDocument} for caching and serving key-stores and trust-stores
 * for {@link eu.europa.esig.dss.service.http.commons.CommonsDataLoader}s.
 *
 * Invoking {@link #openStream()}, {@link #writeTo(OutputStream)} or {@link #save(String)} will trigger key-store content
 * validation if at least {@code minValidationInterval} has passed since the last validation.
 * For each certificate that has expired or will expire in {@code maxWarningPeriod}, a WARNING will be logged.
 */
public class KeyStoreDocument extends CommonDocument {

  private final static Logger logger = LoggerFactory.getLogger(KeyStoreDocument.class);

  private final String path;
  private final String type;
  private final char[] password;
  private final Duration validationInterval;
  private final TemporalAmount warningPeriod;

  private final byte[] rawKeyStoreBytes;

  private Instant lastValidated;

  /**
   * Instantiates this instance of {@link KeyStoreDocument}.
   *
   * @param path path to key-store; see {@link ResourceUtils#getResource(String)}
   * @param type key-store type; defaults to {@link KeyStore#getDefaultType()} if not provided
   * @param password key-store password; can be {@code null}
   * @param minValidationInterval minimum interval between key-store accesses that can trigger key-store validation
   * @param maxWarningPeriod maximum time before a certificate expiry before logging warnings about the certificate starts
   */
  public KeyStoreDocument(String path, String type, String password, Duration minValidationInterval, TemporalAmount maxWarningPeriod) {
    this.path = Objects.requireNonNull(path, "Key-store path cannot be null");
    validationInterval = Objects.requireNonNull(minValidationInterval, "Validation interval cannot be null");
    warningPeriod = Objects.requireNonNull(maxWarningPeriod, "Warning period cannot be null");

    this.type = (type != null) ? type : KeyStore.getDefaultType();
    this.password = (password != null) ? password.toCharArray() : null;

    rawKeyStoreBytes = loadRawKeyStoreBytes(path);
    validateKeyStoreIfLastValidationExpired();
  }

  @Override
  public InputStream openStream() {
    validateKeyStoreIfLastValidationExpired();
    return new ByteArrayInputStream(rawKeyStoreBytes);
  }

  @Override
  public void writeTo(OutputStream stream) throws IOException {
    validateKeyStoreIfLastValidationExpired();
    stream.write(rawKeyStoreBytes);
  }

  private static byte[] loadRawKeyStoreBytes(String path) {
    try (InputStream inputStream = ResourceUtils.getResource(path)) {
      return IOUtils.toByteArray(inputStream);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to load key-store from: " + path, e);
    }
  }

  private void validateKeyStoreIfLastValidationExpired() {
    Instant now = Instant.now();

    if (lastValidated != null) {
      Duration difference = Duration.between(lastValidated, now);
      if (difference.compareTo(validationInterval) < 0) {
        return;
      }
    }

    KeyStore keyStore = loadKeyStoreFromRawBytes();
    Instant safeExpiryTime = now.plus(warningPeriod);

    try {
      Enumeration<String> aliases = keyStore.aliases();
      while (aliases.hasMoreElements()) {
        String alias = aliases.nextElement();
        Certificate[] certificates = getCertificatesByAlias(keyStore, alias);
        for (Certificate certificate : certificates) {
          validateCertificate(certificate, alias, now, safeExpiryTime);
        }
      }
    } catch (KeyStoreException e) {
      throw new IllegalStateException("Failed to list key-store entries from key-store: " + path, e);
    }

    lastValidated = now;
  }

  private KeyStore loadKeyStoreFromRawBytes() {
    KeyStore keyStore;
    try {
      keyStore = KeyStore.getInstance(type);
    } catch (KeyStoreException e) {
      throw new IllegalStateException("Failed to create key-store of type: " + type, e);
    }
    try (InputStream inputStream = new ByteArrayInputStream(rawKeyStoreBytes)) {
      keyStore.load(inputStream, password);
    } catch (CertificateException | IOException | NoSuchAlgorithmException e) {
      throw new IllegalStateException("Failed to load key-store from: " + path, e);
    }
    return keyStore;
  }

  private void validateCertificate(Certificate certificate, String alias, Instant currentTime, Instant safeExpiryTime) {
    if (certificate instanceof X509Certificate) {
      X509Certificate x509Certificate = (X509Certificate) certificate;
      Instant timeOfExpiring = x509Certificate.getNotAfter().toInstant();
      if (timeOfExpiring.isBefore(currentTime)) {
        logger.warn(
                "Certificate from \"{}\" has already expired ({}) - alias: \"{}\"; subject: \"{}\"",
                path, timeOfExpiring, alias, x509Certificate.getSubjectDN()
        );
      } else if (timeOfExpiring.isBefore(safeExpiryTime)) {
        long daysUntilExpiring = Duration.between(timeOfExpiring, safeExpiryTime).toDays();
        logger.warn(
                "Certificate from \"{}\" expires ({}) in about {} day(s) - alias: \"{}\"; subject: \"{}\"",
                path, timeOfExpiring, daysUntilExpiring, alias, x509Certificate.getSubjectDN()
        );
      }
    } else {
      logger.warn(
              "Certificate from \"{}\" is of unrecognized type: \"{}\"; alias: \"{}\"",
              path, certificate.getClass().getCanonicalName(), alias
      );
    }
  }

  private static Certificate[] getCertificatesByAlias(KeyStore keyStore, String alias) throws KeyStoreException {
    Certificate[] certificateChain = keyStore.getCertificateChain(alias);
    if (ArrayUtils.isNotEmpty(certificateChain)) {
      return certificateChain;
    }
    Certificate certificate = keyStore.getCertificate(alias);
    if (certificate != null) {
      return new Certificate[] {certificate};
    }
    return new Certificate[0];
  }

}
