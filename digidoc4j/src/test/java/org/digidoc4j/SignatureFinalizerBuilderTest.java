package org.digidoc4j;

import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.impl.SignatureFinalizer;
import org.digidoc4j.impl.asic.AsicSignatureFinalizer;
import org.digidoc4j.impl.asic.asice.AsicESignatureFinalizer;
import org.digidoc4j.impl.asic.asice.bdoc.BDocSignatureFinalizer;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.digidoc4j.Container.DocumentType.ASICE;
import static org.digidoc4j.Container.DocumentType.ASICS;
import static org.digidoc4j.Container.DocumentType.BDOC;
import static org.digidoc4j.Container.DocumentType.DDOC;
import static org.junit.Assert.assertTrue;

public class SignatureFinalizerBuilderTest {

  @Test
  public void bdocFinalizerFromBdocContainer() {
    Container container = ContainerBuilder.aContainer(BDOC).build();
    SignatureFinalizer signatureFinalizer = SignatureFinalizerBuilder.aFinalizer(container, new SignatureParameters());
    assertTrue(signatureFinalizer instanceof BDocSignatureFinalizer);
  }

  @Test
  public void asiceFinalizerFromAsiceContainer() {
    Container container = ContainerBuilder.aContainer(ASICE).build();
    SignatureFinalizer signatureFinalizer = SignatureFinalizerBuilder.aFinalizer(container, new SignatureParameters());
    assertTrue(signatureFinalizer instanceof AsicESignatureFinalizer);
  }

  @Test
  public void asicFinalizerFromAsicsContainer() {
    Container container = ContainerBuilder.aContainer(ASICS).build();
    SignatureFinalizer signatureFinalizer = SignatureFinalizerBuilder.aFinalizer(container, new SignatureParameters());
    assertTrue(signatureFinalizer instanceof AsicSignatureFinalizer);
  }

  @Test(expected = NotSupportedException.class)
  public void finalizerFromContainer_notSupportedContainerType() {
    Container container = ContainerBuilder.aContainer(DDOC).build();
    SignatureFinalizerBuilder.aFinalizer(container, new SignatureParameters());
  }

  @Test
  public void bdocFinalizerFromDataFiles() {
    SignatureFinalizer signatureFinalizer = buildSignatureFinalizerFromDataFiles(BDOC);
    assertTrue(signatureFinalizer instanceof BDocSignatureFinalizer);
  }

  @Test
  public void asiceFinalizerFromDataFiles() {
    SignatureFinalizer signatureFinalizer = buildSignatureFinalizerFromDataFiles(ASICE);
    assertTrue(signatureFinalizer instanceof AsicESignatureFinalizer);
  }

  @Test
  public void asicsFinalizerFromDataFiles() {
    SignatureFinalizer signatureFinalizer = buildSignatureFinalizerFromDataFiles(ASICS);
    assertTrue(signatureFinalizer instanceof AsicSignatureFinalizer);
  }

  @Test(expected = NotSupportedException.class)
  public void finalizerFromDataFiles_notSupportedContainerType() {
    SignatureFinalizer signatureFinalizer = buildSignatureFinalizerFromDataFiles(DDOC);
    assertTrue(signatureFinalizer instanceof BDocSignatureFinalizer);
  }

  private SignatureFinalizer buildSignatureFinalizerFromDataFiles(Container.DocumentType documentType) {
    List<DataFile> dataFiles = new ArrayList<>();
    return SignatureFinalizerBuilder.aFinalizer(dataFiles, new SignatureParameters(), new Configuration(), documentType);
  }
}
