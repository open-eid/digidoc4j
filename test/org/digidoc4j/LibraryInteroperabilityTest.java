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

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.factory.DigiDocFactory;
import ee.sk.utils.ConfigManager;
import org.digidoc4j.impl.DigiDoc4JTestHelper;
import org.digidoc4j.signers.PKCS12SignatureToken;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertTrue;

public class LibraryInteroperabilityTest extends DigiDoc4JTestHelper {

    private final static Logger logger = LoggerFactory.getLogger(LibraryInteroperabilityTest.class);

    @Rule
    public TemporaryFolder testFolder = new TemporaryFolder();
    private File tempFile;
    private PKCS12SignatureToken PKCS12_SIGNER;

    @Before
    public void setUp() throws Exception {
        PKCS12_SIGNER = new PKCS12SignatureToken("testFiles/signout.p12", "test".toCharArray());
        tempFile = testFolder.newFile("test.bdoc");
    }

    @Test
    public void verifyWithJDigidoc() throws Exception {
        String containerFilePath = tempFile.getPath();
        createSignedContainerWithDigiDoc4j(containerFilePath);
        validateContainerWithJDigiDoc(containerFilePath);
    }

    private void createSignedContainerWithDigiDoc4j(String containerFilePath) {
        Configuration configuration = new Configuration(Configuration.Mode.TEST);
        Container container = ContainerBuilder.
            aContainer().
            withConfiguration(configuration).
            withType("BDOC").
            withDataFile("testFiles/test.txt", "text/plain").
            build();
        signContainer(container, PKCS12_SIGNER);
        signContainer(container, PKCS12_SIGNER);
        logger.debug("Saving test file temporarily to " + containerFilePath);
        container.saveAsFile(containerFilePath);
    }

    private void signContainer(Container container, PKCS12SignatureToken signatureToken) {
        Signature signature = SignatureBuilder.
            aSignature().
            withContainer(container).
            withSignatureProfile(SignatureProfile.LT_TM).
            withSignatureToken(signatureToken).
            invokeSigning();
        container.addSignature(signature);
    }

    private void validateContainerWithJDigiDoc(String containerFilePath) throws DigiDocException {
        String cfgFile = "testFiles/jdigidoc.cfg";
        ConfigManager.init(cfgFile);
        boolean isBdoc = true;
        List errors = new ArrayList();
        DigiDocFactory digFac = ConfigManager.instance().getDigiDocFactory();
        digFac.readSignedDocOfType(containerFilePath, isBdoc, errors);
        assertTrue(getJDigiDocErrorMessage(errors), errors.isEmpty());
    }

    private String getJDigiDocErrorMessage(List errors) {
        String msg = "";
        for(Object error : errors) {
            msg += error.toString() + "; ";
        }
        return msg;
    }
}
