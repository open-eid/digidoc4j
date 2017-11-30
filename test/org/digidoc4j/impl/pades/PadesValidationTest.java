package org.digidoc4j.impl.pades;

import org.digidoc4j.Configuration;
import org.digidoc4j.Constant;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ValidationResult;
import org.junit.Assert;
import org.junit.Test;

import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;

/**
 * Created by Andrei on 20.11.2017.
 */
public class PadesValidationTest {

  @Test
  public void padesValidationTestTwoSignature(){

    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    Container container = ContainerBuilder.
        aContainer("PADES").
        withConfiguration(configuration).
        fromExistingFile("testFiles\\valid-containers\\hello_signed_INCSAVE_signed_EDITED.pdf").
        build();

    ValidationResult result = container.validate();

    Assert.assertFalse(result.isValid());

    Assert.assertEquals(4, result.getErrors().size());
    Assert.assertEquals("The certificate chain for signature is not trusted, there is no trusted anchor.", result.getErrors().get(0).getMessage() );
    Assert.assertEquals("The certificate path is not trusted!", result.getErrors().get(1).getMessage() );
    Assert.assertEquals("The reference data object(s) is not intact!", result.getErrors().get(2).getMessage());
    Assert.assertEquals("The certificate path is not trusted!", result.getErrors().get(3).getMessage());
  }

  @Test
  public void padesValidationTestOneSignature(){

    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    Container container = ContainerBuilder.
        aContainer(Constant.PADES_CONTAINER_TYPE).
        withConfiguration(configuration).
        fromExistingFile("testFiles\\valid-containers\\EE_AS-P-BpLT-V-009.pdf").
        build();

    ValidationResult result = container.validate();

    Assert.assertFalse(result.isValid());

    Assert.assertEquals(2, result.getErrors().size());
    Assert.assertEquals(3, result.getWarnings().size());
    Assert.assertEquals("The certificate chain for signature is not trusted, there is no trusted anchor.", result.getErrors().get(0).getMessage() );
    Assert.assertEquals("The certificate path is not trusted!", result.getErrors().get(1).getMessage() );
    Assert.assertEquals("The certificate chain for timestamp is not trusted, there is no trusted anchor.", result.getWarnings().get(0).getMessage());
    Assert.assertEquals("The signature/seal is an INDETERMINATE AdES!", result.getWarnings().get(1).getMessage());
    Assert.assertEquals("Authority info access is not present!", result.getWarnings().get(2).getMessage());

    Assert.assertEquals(Indication.INDETERMINATE, result.getIndication("id-009b65608f1f1a0c8aac097b4d83b389780e552845d04b66868301a5cf0ed8ba"));
    Assert.assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, result.getSubIndication("id-009b65608f1f1a0c8aac097b4d83b389780e552845d04b66868301a5cf0ed8ba"));
  }
}