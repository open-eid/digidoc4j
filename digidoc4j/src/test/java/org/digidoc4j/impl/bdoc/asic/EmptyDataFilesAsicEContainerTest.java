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

import org.digidoc4j.Configuration;
import org.digidoc4j.Constant;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.exceptions.InvalidDataFileException;
import org.digidoc4j.impl.asic.EmptyDataFilesContainerTest;
import org.digidoc4j.test.TestAssert;
import org.junit.Assert;
import org.junit.Test;

import static org.junit.Assert.assertThrows;

public class EmptyDataFilesAsicEContainerTest extends EmptyDataFilesContainerTest {

  @Override
  protected void before() {
    configuration = Configuration.of(Configuration.Mode.TEST);
  }

  @Override
  protected Container.DocumentType getDocumentType() {
    return Container.DocumentType.ASICE;
  }

  @Test
  public void testValidateUnsignedContainerWithEmptyDataFiles() {
    Container container = loadUnsignedContainerWithEmptyDataFiles();

    ContainerValidationResult validationResult = container.validate();

    Assert.assertTrue(validationResult.isValid());
    Assert.assertNotNull(validationResult.getWarnings());
    TestAssert.assertContainsExactSetOfErrors(validationResult.getWarnings(),
            "Data file 'empty-file-2.txt' is empty",
            "Data file 'empty-file-4.txt' is empty"
    );
    Assert.assertNotNull(validationResult.getContainerWarnings());
    TestAssert.assertContainsExactSetOfErrors(validationResult.getContainerWarnings(),
            "Data file 'empty-file-2.txt' is empty",
            "Data file 'empty-file-4.txt' is empty"
    );
  }

  @Test
  public void testValidateSignedContainerWithEmptyDataFiles() {
    Container container = loadSignedContainerWithEmptyDataFiles();

    ContainerValidationResult validationResult = container.validate();

    Assert.assertTrue(validationResult.isValid());
    Assert.assertNotNull(validationResult.getWarnings());
    TestAssert.assertContainsExactSetOfErrors(validationResult.getWarnings(),
            "Data file 'empty-file-2.txt' is empty",
            "Data file 'empty-file-4.txt' is empty"
    );
    Assert.assertNotNull(validationResult.getContainerWarnings());
    TestAssert.assertContainsExactSetOfErrors(validationResult.getContainerWarnings(),
            "Data file 'empty-file-2.txt' is empty",
            "Data file 'empty-file-4.txt' is empty"
    );
  }

  @Test
  public void testInvokeSigningForUnsignedContainerWithEmptyDataFiles() {
    Container container = loadUnsignedContainerWithEmptyDataFiles();

    InvalidDataFileException caughtException = assertThrows(
            InvalidDataFileException.class,
            () -> SignatureBuilder.aSignature(container)
                    .withSignatureToken(pkcs12Esteid2018SignatureToken)
                    .invokeSigning()
    );

    Assert.assertEquals("Cannot sign empty datafile: empty-file-2.txt", caughtException.getMessage());
    TestAssert.assertSuppressed(caughtException, InvalidDataFileException.class, "Cannot sign empty datafile: empty-file-4.txt");
  }

  @Test
  public void testBuildDataToSignForUnsignedContainerWithEmptyDataFiles() {
    Container container = loadUnsignedContainerWithEmptyDataFiles();

    InvalidDataFileException caughtException = assertThrows(
            InvalidDataFileException.class,
            () -> SignatureBuilder.aSignature(container)
                    .withSignatureToken(pkcs12Esteid2018SignatureToken)
                    .buildDataToSign()
    );

    Assert.assertEquals("Cannot sign empty datafile: empty-file-2.txt", caughtException.getMessage());
    TestAssert.assertSuppressed(caughtException, InvalidDataFileException.class, "Cannot sign empty datafile: empty-file-4.txt");
  }

  @Test
  public void testInvokeSigningForSignedContainerWithEmptyDataFiles() {
    Container container = loadSignedContainerWithEmptyDataFiles();

    InvalidDataFileException caughtException = assertThrows(
            InvalidDataFileException.class,
            () -> SignatureBuilder.aSignature(container)
                    .withSignatureToken(pkcs12SignatureToken)
                    .invokeSigning()
    );

    Assert.assertEquals("Cannot sign empty datafile: empty-file-2.txt", caughtException.getMessage());
    TestAssert.assertSuppressed(caughtException, InvalidDataFileException.class, "Cannot sign empty datafile: empty-file-4.txt");
  }

  @Test
  public void testBuildDataToSignForSignedContainerWithEmptyDataFiles() {
    Container container = loadSignedContainerWithEmptyDataFiles();

    InvalidDataFileException caughtException = assertThrows(
            InvalidDataFileException.class,
            () -> SignatureBuilder.aSignature(container)
                    .withSignatureToken(pkcs12SignatureToken)
                    .buildDataToSign()
    );

    Assert.assertEquals("Cannot sign empty datafile: empty-file-2.txt", caughtException.getMessage());
    TestAssert.assertSuppressed(caughtException, InvalidDataFileException.class, "Cannot sign empty datafile: empty-file-4.txt");
  }

  private Container loadUnsignedContainerWithEmptyDataFiles() {
    Container container = ContainerOpener
            .open("src/test/resources/testFiles/valid-containers/unsigned-container-with-empty-datafiles.asice", configuration);
    Assert.assertEquals(Constant.ASICE_CONTAINER_TYPE, container.getType());
    return container;
  }

  private Container loadSignedContainerWithEmptyDataFiles() {
    Container container = ContainerOpener
            .open("src/test/resources/testFiles/valid-containers/signed-container-with-empty-datafiles.asice", configuration);
    Assert.assertEquals(Constant.ASICE_CONTAINER_TYPE, container.getType());
    return container;
  }

}
