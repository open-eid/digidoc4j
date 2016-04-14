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

import java.io.ByteArrayInputStream;
import java.util.List;

import org.apache.xml.security.signature.Reference;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.Signature;
import org.digidoc4j.testutils.TestDataBuilder;
import org.digidoc4j.utils.AbstractSigningTests;
import org.junit.Test;

/** 
 * This test is testing a "hack" feature that will probably be rolled back later.
 */
public class UriEncodingTest extends AbstractSigningTests {
    @Test
    public void signatureReferencesUseUriEncodingButManifestUsesPlainUtf8() throws InterruptedException {
        Signature signature = sign();
        signature.validateSignature();
        List<Reference> referencesInSignature = ((BDocSignature)signature).getOrigin().getReferences();
        assertEquals("dds_J%C3%9CRI%C3%96%C3%96%20%E2%82%AC%20%C5%BE%C5%A0%20p%C3%A4ev.txt", referencesInSignature.get(0).getURI());
        // TODO: Also write an assertion to verify that the manifest file does NOT use URI encoding
    }
    
    protected Signature sign() {
        Container container = ContainerBuilder.
            aContainer().
            withConfiguration(new Configuration(Configuration.Mode.TEST)).
            withDataFile(new ByteArrayInputStream("file contents".getBytes()), "dds_JÜRIÖÖ € žŠ päev.txt", "application/octet-stream").
            build();
        Signature signature = TestDataBuilder.signContainer(container);
        return signature;
    }
}
