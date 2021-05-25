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
        Assert.assertEquals(2, validationResult.getWarnings().size());
        TestAssert.assertContainsError("Data file 'empty-file-2.txt' is empty", validationResult.getWarnings());
        TestAssert.assertContainsError("Data file 'empty-file-4.txt' is empty", validationResult.getWarnings());
        Assert.assertNotNull(validationResult.getContainerWarnings());
        Assert.assertEquals(2, validationResult.getContainerWarnings().size());
        TestAssert.assertContainsError("Data file 'empty-file-2.txt' is empty", validationResult.getContainerWarnings());
        TestAssert.assertContainsError("Data file 'empty-file-4.txt' is empty", validationResult.getContainerWarnings());
    }

    @Test
    public void testValidateSignedContainerWithEmptyDataFiles() {
        Container container = loadSignedContainerWithEmptyDataFiles();

        ContainerValidationResult validationResult = container.validate();

        Assert.assertTrue(validationResult.isValid());
        Assert.assertNotNull(validationResult.getWarnings());
        Assert.assertEquals(2, validationResult.getWarnings().size());
        TestAssert.assertContainsError("Data file 'empty-file-2.txt' is empty", validationResult.getWarnings());
        TestAssert.assertContainsError("Data file 'empty-file-4.txt' is empty", validationResult.getWarnings());
        Assert.assertNotNull(validationResult.getContainerWarnings());
        Assert.assertEquals(2, validationResult.getContainerWarnings().size());
        TestAssert.assertContainsError("Data file 'empty-file-2.txt' is empty", validationResult.getContainerWarnings());
        TestAssert.assertContainsError("Data file 'empty-file-4.txt' is empty", validationResult.getContainerWarnings());
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
