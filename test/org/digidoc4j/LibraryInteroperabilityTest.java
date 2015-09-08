package org.digidoc4j;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.factory.DigiDocFactory;
import ee.sk.utils.ConfigManager;
import org.digidoc4j.impl.DigiDoc4JTestHelper;
import org.digidoc4j.signers.PKCS12Signer;
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
    private PKCS12Signer PKCS12_SIGNER;

    @Before
    public void setUp() throws Exception {
        PKCS12_SIGNER = new PKCS12Signer("testFiles/signout.p12", "test".toCharArray());
        tempFile = testFolder.newFile("test.bdoc");
    }

    @Test
    public void verifyWithJDigidoc() throws Exception {
        String containerFilePath = tempFile.getPath();
        createSignedContainerWithDigiDoc4j(containerFilePath);
        validateContainerWithJDigiDoc(containerFilePath);
    }

    private void createSignedContainerWithDigiDoc4j(String containerFilePath) {
        ContainerFacade container = ContainerFacade.create();
        container.addDataFile("testFiles/test.txt", "text/plain");
        container.setSignatureProfile(ContainerFacade.SignatureProfile.LT_TM);
        container.sign(PKCS12_SIGNER);
        logger.debug("Saving test file temporarily to " + containerFilePath);
        container.save(containerFilePath);
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
