package org.digidoc4j.impl.bdoc.xades;

import static org.junit.Assert.assertNotNull;

import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.Signature;
import org.digidoc4j.X509Cert;
import org.junit.Test;


/**
 * Created by serkp on 6.09.2017.
 */
public class TimemarkSignatureTest {

	@Test
	public void findOcspCertificate() throws Exception {
		Container container = ContainerBuilder.aContainer().fromExistingFile("testFiles/xades/OCSPRigaTest.asice").build();
		Signature signature = container.getSignatures().get(0);
		X509Cert cert = signature.getOCSPCertificate();
		assertNotNull(cert);
	}

}
