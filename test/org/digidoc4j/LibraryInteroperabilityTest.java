/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j;

import static org.digidoc4j.ContainerBuilder.BDOC_CONTAINER_TYPE;
import static org.digidoc4j.SignatureProfile.B_EPES;
import static org.digidoc4j.SignatureProfile.LT_TM;
import static org.digidoc4j.testutils.TestDataBuilder.createContainerWithFile;
import static org.digidoc4j.testutils.TestDataBuilder.open;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.digidoc4j.impl.DigiDoc4JTestHelper;
import org.digidoc4j.impl.ddoc.ConfigManagerInitializer;
import org.digidoc4j.signers.PKCS12SignatureToken;
import org.digidoc4j.testutils.TestDataBuilder;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.factory.DigiDocFactory;
import ee.sk.utils.ConfigManager;

public class LibraryInteroperabilityTest extends DigiDoc4JTestHelper {

    private final static Logger logger = LoggerFactory.getLogger(LibraryInteroperabilityTest.class);
    private static final Configuration TEST_CONF = new Configuration(Configuration.Mode.TEST);
    private static final Configuration PROD_CONF = new Configuration(Configuration.Mode.PROD);
    private static final ConfigManagerInitializer configManagerInitializer = new ConfigManagerInitializer();

    @Rule
    public TemporaryFolder testFolder = new TemporaryFolder();
    private String tempFilePath;
    private PKCS12SignatureToken signatureToken;

    @Before
    public void setUp() throws Exception {
        signatureToken = new PKCS12SignatureToken("testFiles/p12/signout.p12", "test".toCharArray());
        tempFilePath = testFolder.newFile("test.bdoc").getPath();
        configManagerInitializer.initConfigManager(TEST_CONF);
    }

    @Test
    public void verifyWithJDigidoc() throws Exception {
        createSignedContainerWithDigiDoc4j(tempFilePath);
        validateContainerWithJDigiDoc(tempFilePath);
    }

    @Test
    public void verifyLibdigidocTS_SignatureWithDigiDoc4j() {
        Container container = ContainerBuilder.
            aContainer(BDOC_CONTAINER_TYPE).
            fromExistingFile("testFiles/invalid-containers/Libdigidoc_created_tsa_signature_TS.bdoc").
            withConfiguration(PROD_CONF).
            build();
        validateContainer(container);
    }

    @Test
    public void verifyAddingSignatureToJDigiDocContainer() throws Exception {
        Container container = ContainerBuilder.
            aContainer(BDOC_CONTAINER_TYPE).
            fromExistingFile("testFiles/valid-containers/DigiDocService_spec_est.pdf-TM-j.bdoc").
            withConfiguration(TEST_CONF).
            build();
        TestDataBuilder.signContainer(container);
        validateContainer(container);
        container.saveAsFile(tempFilePath);
        container = TestDataBuilder.open(tempFilePath);
        validateContainer(container);
        validateContainerWithJDigiDoc(tempFilePath);
    }

    @Test
    public void verifyAddingMobileIdSignature_extractedByjDigidoc_shouldBeValid() throws Exception {
        Container container = ContainerBuilder.
            aContainer(BDOC_CONTAINER_TYPE).
            withConfiguration(PROD_CONF).
            withDataFile(new FileInputStream("testFiles/special-char-files/pdf-containing-xml.pdf"), "Sularaha sissemakse.pdf", "application/octet-stream").
            build();
        Signature signature = openSignature(container, "testFiles/xades/bdoc-tm-jdigidoc-mobile-id.xml");
        container.addSignature(signature);
        assertTrue(container.validate().isValid());
        container.saveAsFile(tempFilePath);
        validateContainerWithJDigiDoc(tempFilePath);
    }

    @Test
    public void extendEpesToLtTm_validateWithJdigidoc() throws Exception {
        Container container = createContainerWithFile("testfiles/helper-files/test.txt", "text/plain");
        TestDataBuilder.signContainer(container, B_EPES);
        container.saveAsFile(tempFilePath);
        container = open(tempFilePath);
        container.extendSignatureProfile(LT_TM);
        String extendedContainerPath = testFolder.newFile("extended.bdoc").getPath();
        container.saveAsFile(extendedContainerPath);
        validateContainerWithJDigiDoc(extendedContainerPath);
    }

    private void createSignedContainerWithDigiDoc4j(String containerFilePath) {
        Container container = ContainerBuilder.
            aContainer(BDOC_CONTAINER_TYPE).
            withConfiguration(TEST_CONF).
            withDataFile("testfiles/helper-files/test.txt", "text/plain").
            build();
        signContainer(container, signatureToken);
        signContainer(container, signatureToken);
        logger.debug("Saving test file temporarily to " + containerFilePath);
        container.saveAsFile(containerFilePath);
    }

    private void signContainer(Container container, PKCS12SignatureToken signatureToken) {
        Signature signature = SignatureBuilder.
            aSignature(container).
            withSignatureProfile(SignatureProfile.LT_TM).
            withSignatureToken(signatureToken).
            invokeSigning();
        container.addSignature(signature);
    }

    private void validateContainerWithJDigiDoc(String containerFilePath) throws DigiDocException {
        boolean isBdoc = true;
        List errors = new ArrayList();
        DigiDocFactory digFac = ConfigManager.instance().getDigiDocFactory();
        digFac.readSignedDocOfType(containerFilePath, isBdoc, errors);
        assertTrue(getJDigiDocErrorMessage(errors), errors.isEmpty());
    }

    protected void validateContainer(Container container) {
        ValidationResult result = container.validate();
        assertTrue(result.isValid());
    }

    private String getJDigiDocErrorMessage(List errors) {
        String msg = "";
        for(Object error : errors) {
            msg += error.toString() + "; ";
        }
        return msg;
    }

    private Signature openSignature(Container container, String pathname) throws IOException {
        byte[] signatureBytes = FileUtils.readFileToByteArray(new File(pathname));
        Signature signature = SignatureBuilder.
            aSignature(container).
            openAdESSignature(signatureBytes);
        return signature;
    }
}
