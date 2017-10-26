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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.util.List;

import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.reference.ReferenceData;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.Signature;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.impl.DigiDoc4JTestHelper;
import org.digidoc4j.impl.bdoc.xades.XadesSignature;
import org.digidoc4j.testutils.TestDataBuilder;
import org.junit.Ignore;
import org.junit.Test;

public class UriEncodingTest extends DigiDoc4JTestHelper {

    @Test
    // DetachedSignatureBuilder.createReference(...) uses UTF-8 from dss5.0
    public void signatureReferencesUseUriEncodingButManifestUsesPlainUtf8() throws InterruptedException {
        String fileName = "dds_JÜRIÖÖ € žŠ päev.txt";
        String expectedEncoding = "dds_J%C3%9CRI%C3%96%C3%96%20%E2%82%AC%20%C5%BE%C5%A0%20p%C3%A4ev.txt";
        signAndAssertEncoding(fileName, expectedEncoding);
        // TODO: Also write an assertion to verify that the manifest file does NOT use URI encoding
    }

    @Test
    // DetachedSignatureBuilder.createReference(...) uses UTF-8 from dss5.0
    public void encodeDataFileWithSpecialCharacters() throws Exception {
        String fileName = "et10i_0123456789!#$%&'()+,-. ;=@[]_`}~ et_EE";
        String expectedEncoding = "et10i_0123456789%21%23%24%25%26%27%28%29%2B%2C-.%20%3B%3D%40%5B%5D_%60%7D~%20et_EE";
        signAndAssertEncoding(fileName, expectedEncoding);
    }

    @Test
    public void validatePartialEncoding_shouldBeValid() throws Exception {
        Container container = ContainerBuilder.
            aContainer().
            fromExistingFile("testFiles/valid-containers/et10_0123456789!#$%&'()+,-. ;=@[]_`}- et_EE_utf8.zip-d_ec.bdoc").
            build();
        ValidationResult result = container.validate();
        assertTrue(result.isValid());
    }

    @Test
    //@Ignore("https://www.pivotaltracker.com/story/show/125469911")
    public void validateContainer_withWhitespaceEncodedAsPlus_shouldBeValid() throws Exception {
        Container container = ContainerBuilder.
            aContainer().
            fromExistingFile("testFiles/valid-containers/M1n1 Testäöüõ!.txt-TS-d4j.bdoc").
            build();
        ValidationResult result = container.validate();
        assertTrue(result.isValid());
    }

    private void signAndAssertEncoding(String fileName, String expectedEncoding) {
        Signature signature = sign(fileName);
        assertTrue(signature.validateSignature().isValid());
        List<Reference> referencesInSignature = ((BDocSignature)signature).getOrigin().getReferences();
        assertEquals(expectedEncoding, referencesInSignature.get(0).getURI());
    }

    protected Signature sign(String fileName) {
        Container container = ContainerBuilder.
            aContainer().
            withConfiguration(new Configuration(Configuration.Mode.TEST)).
            withDataFile(new ByteArrayInputStream("file contents".getBytes()), fileName, "application/octet-stream").
            build();
        Signature signature = TestDataBuilder.signContainer(container);
        return signature;
    }
}
