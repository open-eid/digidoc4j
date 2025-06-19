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

import org.digidoc4j.AbstractTest;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.impl.asic.AsicContainer;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

/**
 * Created by Andrei on 15.11.2017.
 */

public class AsicSContainerTest extends AbstractTest {

  @Test(expected = DigiDoc4JException.class)
  public void testAddSignatureToAsicSContainer() throws IOException {
    this.createSignatureBy(this.createNonEmptyContainer(Container.DocumentType.ASICS, 1), this.pkcs12SignatureToken);
  }

  @Test(expected = DigiDoc4JException.class)
  public void testBuildAsicSContainerWithTwoDataFiles() throws IOException {
    this.createNonEmptyContainer(Container.DocumentType.ASICS, 2);
  }

  @Test
  public void testAddingDatafileToContainerWithExistingDatafile() throws IOException {
    Container container = this.createNonEmptyContainer(Container.DocumentType.ASICS, 1);
    DigiDoc4JException exception = assertThrows(DigiDoc4JException.class,
            () -> container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain"));
    assertThat(exception.getMessage(), equalTo("Datafile already exists. ASiC-S container can only contain 1 datafile."));
  }

  @Test(expected = DigiDoc4JException.class)
  public void testExistingAsicSContainerFromPath() {
    Container container = ContainerBuilder.aContainer(Container.DocumentType.ASICS)
        .fromExistingFile("src/test/resources/testFiles/valid-containers/testasics.asics").build();
    //cannot add second file to existing container
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testExistingAsicSContainerFromZIPPath() {
    Container container = ContainerBuilder.aContainer(Container.DocumentType.ASICS).
        fromExistingFile("src/test/resources/testFiles/valid-containers/testasics.zip").build();
    //cannot add second file to existing container
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testExistingAsicSContainerFromStream() throws IOException {
    try (InputStream stream = new FileInputStream(new File("src/test/resources/testFiles/valid-containers/testasics.asics"))) {
      Container container = ContainerBuilder.aContainer(Container.DocumentType.ASICS).fromStream(stream).build();
      //cannot add second file to existing container
      container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    }
  }

  @Test
  public void testExistingAsicSContainerWithSingleSignature() {
    Container container = ContainerBuilder.aContainer(Container.DocumentType.ASICS)
            .fromExistingFile("src/test/resources/testFiles/valid-containers/asics-1-signature.asics").build();
    assertTrue(container.validate().isValid());
  }

  @Test
  public void testExistingAsicSContainerWithTwoSignaturesInDifferentFiles() {
    Container container = ContainerBuilder.aContainer(Container.DocumentType.ASICS)
            .fromExistingFile("src/test/resources/testFiles/invalid-containers/asics-2-signatures-in-different-files.asics").build();
    ValidationResult result = container.validate();
    assertFalse(result.isValid());
    assertEquals("ASICS container can only contain single signature file", result.getErrors().get(0).getMessage());
  }

  @Test
  public void testExistingAsicSContainerWithTwoSignaturesInDifferentFiles2_withoutGivingContainerType() {
    Container container = ContainerBuilder.aContainer()
            .fromExistingFile("src/test/resources/testFiles/invalid-containers/asics-2-signatures-in-different-files.asics").build();
    ValidationResult result = container.validate();
    assertFalse(result.isValid());
    assertEquals("ASICS container can only contain single signature file", result.getErrors().get(0).getMessage());
  }

  @Test
  public void testSignatureExtensionValidationWithoutSignature() {
    AsicContainer container = (AsicContainer) createNonEmptyContainerBy(Container.DocumentType.ASICS);

    Map<String, DigiDoc4JException> validationErrors = container.getExtensionValidationErrors(SignatureProfile.LT_TM);

    assertEquals(0, validationErrors.size());
  }

  @Test
  @Ignore("DD4J-1276")
  public void testSignatureExtensionValidationFromLtToLtaWithExpiredSignerCertificate() {
    AsicContainer container = (AsicContainer) ContainerBuilder.aContainer(Container.DocumentType.ASICS)
            .fromExistingFile("src/test/resources/testFiles/valid-containers/asics-1-signature.asics").build();

    Map<String, DigiDoc4JException> validationErrors = container.getExtensionValidationErrors(SignatureProfile.LTA);

    assertEquals(1, validationErrors.size());
    DigiDoc4JException exception = validationErrors.get("S-B7FFF744E34309E3DF135AAF64A990E9FEA84AD08404A2FE5260610C8A494398");
    assertEquals("Validating the signature with DSS failed", exception.getMessage());
    assertThat(exception.getCause().getMessage(), containsString("The signing certificate has expired and there is no POE during its validity range"));
  }

  @Test
  public void testLtSignatureExtensionValidationFromLtToLtWithExpiredSignerCertificate() {
    AsicContainer container = (AsicContainer) ContainerBuilder.aContainer(Container.DocumentType.ASICS)
            .fromExistingFile("src/test/resources/testFiles/valid-containers/asics-1-signature.asics").build();

    Map<String, DigiDoc4JException> validationErrors = container.getExtensionValidationErrors(SignatureProfile.LT);

    assertEquals(1, validationErrors.size());
    DigiDoc4JException exception = validationErrors.get("S-B7FFF744E34309E3DF135AAF64A990E9FEA84AD08404A2FE5260610C8A494398");
    assertEquals(NotSupportedException.class, exception.getClass());
    assertEquals("Not supported: It is not possible to extend LT signature to LT.", exception.getMessage());
  }

  @Test
  public void testLtSignatureExtensionValidationFromLtToLtTmWithExpiredSignerCertificate() {
    AsicContainer container = (AsicContainer) ContainerBuilder.aContainer(Container.DocumentType.ASICS)
            .fromExistingFile("src/test/resources/testFiles/valid-containers/asics-1-signature.asics").build();

    Map<String, DigiDoc4JException> validationErrors = container.getExtensionValidationErrors(SignatureProfile.LT_TM);

    assertEquals(1, validationErrors.size());
    DigiDoc4JException exception = validationErrors.get("S-B7FFF744E34309E3DF135AAF64A990E9FEA84AD08404A2FE5260610C8A494398");
    assertEquals(NotSupportedException.class, exception.getClass());
    assertEquals("Not supported: It is not possible to extend LT signature to LT_TM.", exception.getMessage());
  }

  @Test
  public void removingNullSignatureDoesNothing() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/asics-1-signature.asics");
    Assert.assertEquals(1, container.getSignatures().size());
    container.removeSignature(null);
    Assert.assertEquals(1, container.getSignatures().size());
  }

}
