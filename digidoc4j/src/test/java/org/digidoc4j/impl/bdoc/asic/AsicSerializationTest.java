/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.bdoc.asic;

import org.apache.commons.lang3.SerializationUtils;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Container;
import org.digidoc4j.DataToSign;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureProfile;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class AsicSerializationTest extends AbstractTest {

  @Test
  public void bdocContainerSigningWithSerialization() {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    assertEquals(0, container.getSignatures().size());
    container = serializeAndAddSignature(container, SignatureProfile.LT);
    assertTrue(container.validate().isValid());
    assertEquals(1, container.getSignatures().size());
    assertTimestampSignature(container.getSignatures().get(0));
    assertBDocContainer(container);
  }

  @Test
  public void asiceContainerSigningWithSerialization() {
    Container container = this.createEmptyContainerBy(Container.DocumentType.ASICE);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    assertEquals(0, container.getSignatures().size());
    container = serializeAndAddSignature(container, SignatureProfile.LT);
    assertTrue(container.validate().isValid());
    assertEquals(1, container.getSignatures().size());
    assertTimestampSignature(container.getSignatures().get(0));
    assertAsicEContainer(container);
  }

  @Test
  public void asiceLtaContainerSigningWithSerialization() {
    Container container = this.createEmptyContainerBy(Container.DocumentType.ASICE);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    assertEquals(0, container.getSignatures().size());
    container = serializeAndAddSignature(container, SignatureProfile.LTA);
    assertTrue(container.validate().isValid());
    assertEquals(1, container.getSignatures().size());
    assertArchiveTimestampSignature(container.getSignatures().get(0));
    assertAsicEContainer(container);
  }

  private Container serializeAndAddSignature(Container container, SignatureProfile signatureProfile) {
    byte[] serializedContainer = SerializationUtils.serialize(container);

    DataToSign dataToSign = SignatureBuilder.aSignature(container)
          .withSigningCertificate(pkcs12SignatureToken.getCertificate())
          .withSignatureProfile(signatureProfile)
          .buildDataToSign();

    byte[] serializedDataToSign = SerializationUtils.serialize(dataToSign);
    dataToSign = SerializationUtils.deserialize(serializedDataToSign);

    byte[] signatureValue = this.sign(dataToSign.getDataToSign(), dataToSign.getDigestAlgorithm());
    Signature signature = dataToSign.finalize(signatureValue);

    container = SerializationUtils.deserialize(serializedContainer);
    container.addSignature(signature);
    return container;
  }
}
