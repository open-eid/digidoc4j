/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl;

import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import org.digidoc4j.impl.asic.SKCommonCertificateVerifier;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotSame;

class SKCommonCertificateVerifierTest {

  @Test
  void skCommonCertificateVerifier_afterDeserialization_shouldRetainSilentAlerts() throws Exception {
    SKCommonCertificateVerifier originalVerifier = new SKCommonCertificateVerifier();

    SKCommonCertificateVerifier deserializedVerifier = serializeAndDeserialize(originalVerifier);

    assertNotSame(originalVerifier, deserializedVerifier);
    assertInstanceOf(SilentOnStatusAlert.class, deserializedVerifier.getAlertOnMissingRevocationData());
    assertInstanceOf(SilentOnStatusAlert.class, deserializedVerifier.getAlertOnNoRevocationAfterBestSignatureTime());
  }

  @Test
  void skCommonCertificateVerifier_whenConstructed_shouldSetSilentAlerts() {
    SKCommonCertificateVerifier verifier = new SKCommonCertificateVerifier();

    assertInstanceOf(SilentOnStatusAlert.class, verifier.getAlertOnMissingRevocationData());
    assertInstanceOf(SilentOnStatusAlert.class, verifier.getAlertOnNoRevocationAfterBestSignatureTime());
  }

  private static SKCommonCertificateVerifier serializeAndDeserialize(SKCommonCertificateVerifier verifier) throws Exception {
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    try (ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream)) {
      objectOutputStream.writeObject(verifier);
    }
    try (ObjectInputStream objectInputStream = new ObjectInputStream(new ByteArrayInputStream(byteArrayOutputStream.toByteArray()))) {
      return (SKCommonCertificateVerifier) objectInputStream.readObject();
    }
  }
}
