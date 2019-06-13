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
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
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
  public void testAsicSContainerWithTwoDataFiles() throws IOException {
    this.createNonEmptyContainer(Container.DocumentType.ASICS, 2);
  }

  @Test(expected = DigiDoc4JException.class)
  public void testExistingAsicSContainerFromPath() throws IOException {
    Container container = ContainerBuilder.aContainer(Container.DocumentType.ASICS)
        .fromExistingFile("src/test/resources/testFiles/valid-containers/testasics.asics").build();
    //cannot add second file to existing container
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testExistingAsicSContainerFromZIPPath() throws IOException {
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
  public void testExistingAsicSContainerWithSingleSingature() {
    Container container = ContainerBuilder.aContainer(Container.DocumentType.ASICS)
            .fromExistingFile("src/test/resources/testFiles/valid-containers/asics-1-signature.asics").build();
    assertTrue(container.validate().isValid());
  }

  @Test
  public void testExistingAsicSContainerWithTwoSingaturesInDifferentFiles() {
    Container container = ContainerBuilder.aContainer(Container.DocumentType.ASICS)
            .fromExistingFile("src/test/resources/testFiles/invalid-containers/asics-2-signatures-in-different-files.asics").build();
    ValidationResult result = container.validate();
    assertFalse(result.isValid());
    assertEquals("ASICS container can only contain single signature file", result.getErrors().get(0).getMessage());
  }

  @Test
  public void testExistingAsicSContainerWithTwoSingaturesInDifferentFiles2_withoutGivingContainerType() {
    Container container = ContainerBuilder.aContainer()
            .fromExistingFile("src/test/resources/testFiles/invalid-containers/asics-2-signatures-in-different-files.asics").build();
    ValidationResult result = container.validate();
    assertFalse(result.isValid());
    assertEquals("ASICS container can only contain single signature file", result.getErrors().get(0).getMessage());
  }

  @Test
  public void removingNullSignatureDoesNothing() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/asics-1-signature.asics");
    Assert.assertEquals(1, container.getSignatures().size());
    container.removeSignature(null);
    Assert.assertEquals(1, container.getSignatures().size());
  }

}
