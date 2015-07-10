package org.digidoc4j.impl;

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.util.List;

import org.apache.xml.security.signature.Reference;
import org.digidoc4j.Container;
import org.digidoc4j.utils.AbstractSigningTests;
import org.digidoc4j.utils.CertificatesForTests;
import org.junit.Test;

/** 
 * This test is testing a "hack" feature that will probably be rolled back later.
 */
public class UriEncodingTest extends AbstractSigningTests {
    @Test
    public void signatureReferencesUseUriEncodingButManifestUsesPlainUtf8() throws InterruptedException {
        BDocContainer container = sign();
        
        List<Reference> referencesInSignature = ((BDocSignature)container.getSignature(0)).getOrigin().getReferences();
        assertEquals("dds_J%C3%9CRI%C3%96%C3%96%20%E2%82%AC%20%C5%BE%C5%A0%20p%C3%A4ev.txt", referencesInSignature.get(0).getURI());
        // TODO: Also write an assertion to verify that the manifest file does NOT use URI encoding
    }
    
    protected BDocContainer sign() {
        BDocContainer container = (BDocContainer) Container.create(createDigiDoc4JConfiguration());
        container.addDataFile(new ByteArrayInputStream("file contents".getBytes()), "dds_JÜRIÖÖ € žŠ päev.txt", "application/octet-stream");
        byte[] hashToSign = prepareSigning(container, CertificatesForTests.SIGN_CERT, createSignatureParameters());
        byte[] signatureValue = signWithRsa(CertificatesForTests.PRIVATE_KEY_FOR_SIGN_CERT, hashToSign);
        container.signRaw(signatureValue);
        return container;
    }
}
