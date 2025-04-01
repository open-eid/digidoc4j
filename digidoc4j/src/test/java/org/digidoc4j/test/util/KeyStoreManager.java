/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.test.util;

import org.digidoc4j.X509Cert;

import java.io.File;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class KeyStoreManager {

  private final KeyStore keyStore;
  private final KeyStore.PasswordProtection passwordProtection;

  public KeyStoreManager(String type, KeyStore.PasswordProtection passwordProtection) {
    this(createInstance(Objects.requireNonNull(type)), passwordProtection);
  }

  public KeyStoreManager(KeyStore keyStore, KeyStore.PasswordProtection passwordProtection) {
    this.keyStore = Objects.requireNonNull(keyStore);
    this.passwordProtection = Objects.requireNonNull(passwordProtection);
    try {
      keyStore.load(null, passwordProtection.getPassword());
    } catch (Exception e) {
      throw new IllegalStateException("Failed to initialize key-store", e);
    }
  }

  public void addTrustedCertificate(String alias, X509Certificate certificate) {
    try {
      keyStore.setCertificateEntry(alias, certificate);
    } catch (KeyStoreException e) {
      throw new IllegalStateException("Failed to add key entry with alias: " + alias, e);
    }
  }

  public void addTrustedCertificate(X509Certificate certificate) {
    String alias = new X509Cert(certificate).getSubjectName(X509Cert.SubjectName.CN);
    addTrustedCertificate(alias, certificate);
  }

  public void addTrustedCertificates(Map<String, X509Certificate> aliasesAndCertificates) {
    aliasesAndCertificates.forEach(this::addTrustedCertificate);
  }

  public void addTrustedCertificates(List<X509Certificate> certificates) {
    certificates.forEach(this::addTrustedCertificate);
  }

  public void addTrustedCertificates(X509Certificate... certificates) {
    addTrustedCertificates(Arrays.asList(certificates));
  }

  public void save(File file) {
    try (OutputStream out = Files.newOutputStream(file.toPath(), StandardOpenOption.WRITE)) {
      keyStore.store(out, passwordProtection.getPassword());
    } catch (Exception e) {
      throw new IllegalStateException("Failed to save key-store to file: " + file, e);
    }
  }

  private static KeyStore createInstance(String keyStoreType) {
    try {
      return KeyStore.getInstance(keyStoreType);
    } catch (KeyStoreException e) {
      throw new IllegalStateException("Failed to create key-store of type: " + keyStoreType, e);
    }
  }

}
