/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.bdoc;

import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.impl.asic.asice.AsicESignature;
import org.digidoc4j.test.TestAssert;
import org.digidoc4j.test.util.TestDataBuilderUtil;
import org.junit.Assert;
import org.junit.Test;

import java.util.List;

import static java.lang.Thread.sleep;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class ExtendingBDocContainerTest extends AbstractTest {

  private static final String B_EPES_CONTAINER_PATH = "src/test/resources/testFiles/valid-containers/bdoc-with-b-epes-signature.bdoc";
  private static final String LT_TM_CONTAINER_PATH = "src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc";
  private static final String ASICE_LTA_CONTAINER_PATH = "src/test/resources/testFiles/valid-containers/valid-asice-lta.asice";

  private String containerLocation;

  @Test
  public void extendFromB_BESToLT() {
    Container container = createNonEmptyContainer();
    createSignatureBy(container, SignatureProfile.B_BES, pkcs12SignatureToken);
    container.saveAsFile(containerLocation);

    Assert.assertEquals(1, container.getSignatures().size());
    Assert.assertNull(container.getSignatures().get(0).getOCSPCertificate());

    container = TestDataBuilderUtil.open(containerLocation);
    container.extendSignatureProfile(SignatureProfile.LT);
    container.saveAsFile(getFileBy("bdoc"));

    Assert.assertEquals(1, container.getSignatures().size());
    Signature signature = container.getSignatures().get(0);

    Assert.assertNotNull(signature.getOCSPCertificate());
    Assert.assertEquals(SignatureProfile.LT, signature.getProfile());
    Assert.assertTrue(container.validate().isValid());
  }

  @Test
  public void extendFromB_BESToLTA() {
    Container container = createNonEmptyContainer();
    createSignatureBy(container, SignatureProfile.B_BES, pkcs12SignatureToken);
    container.saveAsFile(containerLocation);

    Assert.assertEquals(1, container.getSignatures().size());
    Assert.assertNull(container.getSignatures().get(0).getOCSPCertificate());

    container = TestDataBuilderUtil.open(containerLocation);
    container.extendSignatureProfile(SignatureProfile.LTA);
    container.saveAsFile(getFileBy("bdoc"));

    Assert.assertEquals(1, container.getSignatures().size());
    Assert.assertNotNull(container.getSignatures().get(0).getOCSPCertificate());
    List<TimestampToken> archiveTimestamps = getFirstSignatureArchiveTimestamps(container);
    assertEquals("The signature must contain 1 archive timestamp", 1, archiveTimestamps.size());
  }

  @Test
  public void extendFromB_BESToLT_TM_ThrowsException() {
    Container container = createNonEmptyContainer();
    createSignatureBy(container, SignatureProfile.B_BES, pkcs12SignatureToken);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> container.extendSignatureProfile(SignatureProfile.LT_TM)
    );

    assertThat(caughtException.getMessage(), containsString(
            "It is not possible to extend B_BES signature to LT_TM"
    ));
  }

  @Test
  public void extendFromB_EPESToLT_TM_ThrowsException() {
    Container container = ContainerOpener.open(B_EPES_CONTAINER_PATH, Configuration.of(Configuration.Mode.TEST));

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> container.extendSignatureProfile(SignatureProfile.LT_TM)
    );

    assertThat(caughtException.getMessage(), containsString(
            "It is not possible to extend B_EPES signature to LT_TM"
    ));
  }

  @Test
  public void extendFromB_EPESToLT_ThrowsException() {
    Container container = ContainerOpener.open(B_EPES_CONTAINER_PATH, Configuration.of(Configuration.Mode.TEST));

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> container.extendSignatureProfile(SignatureProfile.LT)
    );

    assertThat(caughtException.getMessage(), containsString(
            "It is not possible to extend B_EPES signature to LT"
    ));
  }

  @Test
  public void extendFromB_EPESToLTA_ThrowsException() {
    Container container = ContainerOpener.open(B_EPES_CONTAINER_PATH, Configuration.of(Configuration.Mode.TEST));

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> container.extendSignatureProfile(SignatureProfile.LTA)
    );

    assertThat(caughtException.getMessage(), containsString(
            "It is not possible to extend B_EPES signature to LTA"
    ));
  }

  @Test
  public void extendFromLTToLT_TM_ThrowsException() {
    Container container = createNonEmptyContainer();
    createSignatureBy(container, SignatureProfile.LT, pkcs12SignatureToken);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> container.extendSignatureProfile(SignatureProfile.LT_TM)
    );

    assertThat(caughtException.getMessage(), containsString(
            "It is not possible to extend LT signature to LT_TM"
    ));
  }

  @Test
  public void extendFromLTAToLT_TM_ThrowsException() {
    Container container = createNonEmptyContainer();
    createSignatureBy(container, SignatureProfile.LTA, pkcs12SignatureToken);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> container.extendSignatureProfile(SignatureProfile.LT_TM)
    );

    assertThat(caughtException.getMessage(), containsString(
            "It is not possible to extend LTA signature to LT_TM"
    ));
  }

  @Test
  public void extendFromLTToB_BES_ThrowsException() {
    Container container = createNonEmptyContainer();
    createSignatureBy(container, SignatureProfile.LT, pkcs12SignatureToken);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> container.extendSignatureProfile(SignatureProfile.B_BES)
    );

    assertThat(caughtException.getMessage(), containsString(
            "It is not possible to extend LT signature to B_BES"
    ));
  }

  @Test
  public void extendFromLTToB_EPES_ThrowsException() {
    Container container = createNonEmptyContainer();
    createSignatureBy(container, SignatureProfile.LT, pkcs12SignatureToken);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> container.extendSignatureProfile(SignatureProfile.B_EPES)
    );

    assertThat(caughtException.getMessage(), containsString(
            "It is not possible to extend LT signature to B_EPES"
    ));
  }

  @Test
  public void extendFromLT_TMToLT_ThrowsException() {
    Container container = ContainerOpener.open(LT_TM_CONTAINER_PATH, Configuration.of(Configuration.Mode.TEST));

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> container.extendSignatureProfile(SignatureProfile.LT)
    );

    assertThat(caughtException.getMessage(), containsString(
            "It is not possible to extend LT_TM signature to LT"
    ));
  }

  @Test
  public void extendToWhenConfirmationAlreadyExists() {
    Container initialContainer = createNonEmptyContainer();
    createSignatureBy(initialContainer, SignatureProfile.B_BES, pkcs12SignatureToken);
    initialContainer.saveAsFile(containerLocation);

    Assert.assertEquals(1, initialContainer.getSignatures().size());
    Assert.assertNull(initialContainer.getSignatures().get(0).getOCSPCertificate());

    Container deserializedContainer = TestDataBuilderUtil.open(containerLocation);
    deserializedContainer.extendSignatureProfile(SignatureProfile.LT);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> deserializedContainer.extendSignatureProfile(SignatureProfile.LT)
    );

    assertThat(caughtException.getMessage(), containsString(
            "It is not possible to extend LT signature to LT"
    ));
  }

  @Test
  public void extendToWithMultipleSignatures() {
    Container container = createNonEmptyContainer();
    createSignatureBy(container, SignatureProfile.B_BES, pkcs12SignatureToken);
    createSignatureBy(container, SignatureProfile.B_BES, pkcs12SignatureToken);
    container.saveAsFile(containerLocation);

    Assert.assertEquals(2, container.getSignatures().size());
    Assert.assertNull(container.getSignatures().get(0).getOCSPCertificate());
    Assert.assertNull(container.getSignatures().get(1).getOCSPCertificate());

    container = TestDataBuilderUtil.open(containerLocation);
    container.extendSignatureProfile(SignatureProfile.LT);
    String containerPath = getFileBy("bdoc");
    container.saveAsFile(containerPath);

    container = TestDataBuilderUtil.open(containerPath);

    Assert.assertEquals(2, container.getSignatures().size());
    Assert.assertNotNull(container.getSignatures().get(0).getOCSPCertificate());
    Assert.assertNotNull(container.getSignatures().get(1).getOCSPCertificate());
    Assert.assertTrue(container.validate().isValid());
  }

  @Test
  public void extendToWithMultipleSignaturesAndMultipleFiles() {
    Container container = createNonEmptyContainer();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.xml", "text/xml");
    createSignatureBy(container, SignatureProfile.B_BES, pkcs12SignatureToken);
    createSignatureBy(container, SignatureProfile.B_BES, pkcs12SignatureToken);
    container.saveAsFile(containerLocation);

    Assert.assertEquals(2, container.getSignatures().size());
    Assert.assertEquals(2, container.getDataFiles().size());
    Assert.assertNull(container.getSignatures().get(0).getOCSPCertificate());
    Assert.assertNull(container.getSignatures().get(1).getOCSPCertificate());

    container = TestDataBuilderUtil.open(containerLocation);
    container.extendSignatureProfile(SignatureProfile.LT);
    container.saveAsFile(getFileBy("bdoc"));

    Assert.assertEquals(2, container.getSignatures().size());
    Assert.assertEquals(2, container.getDataFiles().size());
    Assert.assertNotNull(container.getSignatures().get(0).getOCSPCertificate());
    Assert.assertNotNull(container.getSignatures().get(1).getOCSPCertificate());
    Assert.assertTrue(container.validate().isValid());
  }

  @Test
  public void testContainerExtensionFromLTtoLTA() throws InterruptedException {
    Container container = createNonEmptyContainer();
    createSignatureBy(container, SignatureProfile.LT, pkcs12SignatureToken);
    sleep(1100);

    container.extendSignatureProfile(SignatureProfile.LTA);

    Assert.assertNotNull(container.getSignatures().get(0).getOCSPCertificate());
    TestAssert.assertContainerIsValid(container);
    List<TimestampToken> archiveTimestamps = getFirstSignatureArchiveTimestamps(container);
    assertEquals("The signature must contain 1 archive timestamp", 1, archiveTimestamps.size());
  }

  @Test
  public void testContainerExtensionFromLTAtoLTA() {
    Container container = ContainerOpener.open(ASICE_LTA_CONTAINER_PATH, Configuration.of(Configuration.Mode.TEST));

    container.extendSignatureProfile(SignatureProfile.LTA);

    TestAssert.assertContainerIsValid(container);
    Assert.assertEquals(1, container.getSignatures().size());
    List<TimestampToken> archiveTimestamps = getFirstSignatureArchiveTimestamps(container);
    assertEquals("The signature must contain 2 archive timestamps", 2, archiveTimestamps.size());
  }

  private List<TimestampToken> getFirstSignatureArchiveTimestamps(Container container) {
    return ((AsicESignature) container.getSignatures().get(0)).getOrigin().getDssSignature().getArchiveTimestamps();
  }

  @Test
  public void extensionNotPossibleFromLTtoLT() {
    Container container = createNonEmptyContainer();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    createSignatureBy(container, SignatureProfile.LT, pkcs12SignatureToken);

    NotSupportedException caughtException = assertThrows(
            NotSupportedException.class,
            () -> container.extendSignatureProfile(SignatureProfile.LT)
    );

    assertThat(caughtException.getMessage(), containsString(
            "It is not possible to extend LT signature to LT"
    ));
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
     containerLocation = getFileBy("bdoc");
  }

}
