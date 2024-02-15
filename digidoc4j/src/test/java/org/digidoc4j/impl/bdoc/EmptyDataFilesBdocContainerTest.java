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

import org.digidoc4j.Configuration;
import org.digidoc4j.Constant;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.exceptions.InvalidDataFileException;
import org.digidoc4j.impl.asic.EmptyDataFilesContainerTest;
import org.digidoc4j.test.TestAssert;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class EmptyDataFilesBdocContainerTest extends EmptyDataFilesContainerTest {

    @Override
    protected void before() {
        configuration = Configuration.of(Configuration.Mode.TEST);
    }

    @Override
    protected Container.DocumentType getDocumentType() {
        return Container.DocumentType.BDOC;
    }

    @Test
    public void testValidateSignedContainerWithEmptyDataFiles() {
        Container container = loadSignedContainerWithEmptyDataFiles();

        ContainerValidationResult validationResult = container.validate();

        assertTrue(validationResult.isValid());
        assertNotNull(validationResult.getWarnings());
        TestAssert.assertContainsExactSetOfErrors(validationResult.getWarnings(),
                "Data file 'empty-file-2.txt' is empty",
                "Data file 'empty-file-4.txt' is empty"
        );
        assertNotNull(validationResult.getContainerWarnings());
        TestAssert.assertContainsExactSetOfErrors(validationResult.getContainerWarnings(),
                "Data file 'empty-file-2.txt' is empty",
                "Data file 'empty-file-4.txt' is empty"
        );
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

        assertEquals("Cannot sign empty datafile: empty-file-2.txt", caughtException.getMessage());
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

        assertEquals("Cannot sign empty datafile: empty-file-2.txt", caughtException.getMessage());
        TestAssert.assertSuppressed(caughtException, InvalidDataFileException.class, "Cannot sign empty datafile: empty-file-4.txt");
    }

    private Container loadSignedContainerWithEmptyDataFiles() {
        Container container = ContainerOpener
                .open("src/test/resources/testFiles/valid-containers/signed-container-with-empty-datafiles.bdoc", configuration);
        assertEquals(Constant.BDOC_CONTAINER_TYPE, container.getType());
        return container;
    }

}
