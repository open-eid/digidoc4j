/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.bdoc.asic;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.DataLoaderFactory;
import org.digidoc4j.DataToSign;
import org.digidoc4j.OCSPSourceFactory;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureFinalizerBuilder;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.impl.CommonOCSPSource;
import org.digidoc4j.impl.OcspDataLoaderFactory;
import org.digidoc4j.impl.SKOnlineOCSPSource;
import org.digidoc4j.impl.SignatureFinalizer;
import org.digidoc4j.impl.SkOCSPDataLoader;
import org.digidoc4j.impl.SkTimestampDataLoader;
import org.junit.Test;
import org.mockito.Mockito;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;

public class AsicSignatureFinalizerTest extends AbstractTest {

  @Test
  public void asiceLtSignatureFinalization() {
    Container container = createEmptyContainerBy(Container.DocumentType.ASICE);
    container.addDataFile(createTextDataFile("file name", "something"));

    DataToSign dataToSign = SignatureBuilder.aSignature(container)
          .withSigningCertificate(pkcs12SignatureToken.getCertificate())
          .withSignatureProfile(SignatureProfile.LT)
          .buildDataToSign();

    byte[] signatureDigest = sign(dataToSign.getDataToSign(), dataToSign.getDigestAlgorithm());

    SignatureFinalizer signatureFinalizer = SignatureFinalizerBuilder.aFinalizer(container, dataToSign.getSignatureParameters());
    Signature signature = signatureFinalizer.finalizeSignature(signatureDigest);
    assertLtSignature(signature);
    assertValidSignature(signature);
  }

  @Test
  public void asiceLtaSignatureFinalization() {
    Container container = createEmptyContainerBy(Container.DocumentType.ASICE);
    container.addDataFile(createTextDataFile("file name", "something"));

    DataToSign dataToSign = SignatureBuilder.aSignature(container)
          .withSigningCertificate(pkcs12SignatureToken.getCertificate())
          .withSignatureProfile(SignatureProfile.LTA)
          .buildDataToSign();

    byte[] signatureDigest = sign(dataToSign.getDataToSign(), dataToSign.getDigestAlgorithm());

    SignatureFinalizer signatureFinalizer = SignatureFinalizerBuilder.aFinalizer(container, dataToSign.getSignatureParameters());
    Signature signature = signatureFinalizer.finalizeSignature(signatureDigest);
    assertArchiveTimestampSignature(signature);
    assertValidSignature(signature);
  }

  @Test
  public void signatureFinalizerFieldsEqualToDataToSign() {
    Container container = createEmptyContainerBy(Container.DocumentType.ASICE);
    container.addDataFile(createTextDataFile("file name", "something"));

    DataToSign dataToSign = SignatureBuilder.aSignature(container)
          .withSigningCertificate(pkcs12SignatureToken.getCertificate())
          .withSignatureProfile(SignatureProfile.LT)
          .buildDataToSign();

    SignatureFinalizer signatureFinalizer = SignatureFinalizerBuilder.aFinalizer(container, dataToSign.getSignatureParameters());
    assertEquals(dataToSign.getSignatureParameters(), signatureFinalizer.getSignatureParameters());
    assertEquals(dataToSign.getConfiguration(), signatureFinalizer.getConfiguration());
    assertEquals(dataToSign.getDigestAlgorithm(), signatureFinalizer.getSignatureParameters().getSignatureDigestAlgorithm());
  }

  @Test
  public void getDataToSignBytesEqualToValueFromDataToSignObject() {
    Container container = createEmptyContainerBy(Container.DocumentType.ASICE);
    container.addDataFile(createTextDataFile("file name", "something"));

    DataToSign dataToSign = SignatureBuilder.aSignature(container)
          .withSigningCertificate(pkcs12SignatureToken.getCertificate())
          .withSignatureProfile(SignatureProfile.LT)
          .buildDataToSign();

    byte[] dataToSignBytes = dataToSign.getDataToSign();
    byte[] signatureDigest = sign(dataToSignBytes, dataToSign.getDigestAlgorithm());

    SignatureFinalizer signatureFinalizer = SignatureFinalizerBuilder.aFinalizer(container, dataToSign.getSignatureParameters());

    assertThat(dataToSignBytes, equalTo(signatureFinalizer.getDataToBeSigned()));

    Signature signature = signatureFinalizer.finalizeSignature(signatureDigest);
    assertLtSignature(signature);
    assertValidSignature(signature);

    assertThat(dataToSignBytes, equalTo(signatureFinalizer.getDataToBeSigned()));
  }

  @Test
  public void testCustomTspDataLoaderUsedForSigning() {
    configuration = Configuration.of(Configuration.Mode.TEST);
    SkTimestampDataLoader tspDataLoader = new SkTimestampDataLoader(configuration);
    tspDataLoader.setUserAgent("custom-user-agent-string");
    DataLoader dataLoaderSpy = Mockito.spy(tspDataLoader);

    DataLoaderFactory dataLoaderFactory = Mockito.mock(DataLoaderFactory.class);
    Mockito.doReturn(dataLoaderSpy).when(dataLoaderFactory).create();
    configuration.setTspDataLoaderFactory(dataLoaderFactory);

    Signature signature = createSignatureBy(createNonEmptyContainerByConfiguration(), pkcs12SignatureToken);
    assertValidSignature(signature);

    Mockito.verify(dataLoaderFactory, Mockito.times(1)).create();
    Mockito.verify(dataLoaderSpy, Mockito.times(1)).post(Mockito.eq(configuration.getTspSource()), Mockito.any(byte[].class));
    Mockito.verifyNoMoreInteractions(dataLoaderFactory);
  }

  @Test
  public void testCustomOcspDataLoaderUsedForSigning() {
    configuration = Configuration.of(Configuration.Mode.TEST);
    configuration.setPreferAiaOcsp(false);
    SkOCSPDataLoader ocspDataLoader = new SkOCSPDataLoader(configuration);
    ocspDataLoader.setUserAgent("custom-user-agent-string");
    DataLoader dataLoaderSpy = Mockito.spy(ocspDataLoader);

    DataLoaderFactory dataLoaderFactory = Mockito.mock(DataLoaderFactory.class);
    Mockito.doReturn(dataLoaderSpy).when(dataLoaderFactory).create();
    configuration.setOcspDataLoaderFactory(dataLoaderFactory);

    Signature signature = createSignatureBy(createNonEmptyContainerByConfiguration(), pkcs12Esteid2018SignatureToken);
    assertValidSignature(signature);

    Mockito.verify(dataLoaderFactory, Mockito.times(1)).create();
    Mockito.verify(dataLoaderSpy, Mockito.times(1)).post(Mockito.eq(configuration.getOcspSource()), Mockito.any(byte[].class));
    Mockito.verifyNoMoreInteractions(dataLoaderFactory);
  }

  @Test
  public void testCustomAiaDataLoaderUsedForSigning() {
    configuration = Configuration.of(Configuration.Mode.TEST);
    CommonsDataLoader aiaDataLoader = new CommonsDataLoader();
    DataLoader dataLoaderSpy = Mockito.spy(aiaDataLoader);

    DataLoaderFactory dataLoaderFactory = Mockito.mock(DataLoaderFactory.class);
    Mockito.doReturn(dataLoaderSpy).when(dataLoaderFactory).create();
    configuration.setAiaDataLoaderFactory(dataLoaderFactory);

    Signature signature = createSignatureBy(createNonEmptyContainerByConfiguration(), pkcs12SignatureToken);
    assertValidSignature(signature);

    Mockito.verify(dataLoaderFactory, Mockito.atLeast(1)).create();
    Mockito.verify(dataLoaderSpy, Mockito.times(1)).get("http://www.sk.ee/certs/TEST_of_EE_Certification_Centre_Root_CA.der.crt");
    Mockito.verifyNoMoreInteractions(dataLoaderFactory);
  }

  @Test
  public void testCustomOcspSourceUsedForSigning() {
    configuration = Configuration.of(Configuration.Mode.TEST);
    SKOnlineOCSPSource source = new CommonOCSPSource(configuration);
    DataLoader dataLoader = new OcspDataLoaderFactory(configuration).create();
    source.setDataLoader(dataLoader);
    SKOnlineOCSPSource sourceSpy = Mockito.spy(source);
    OCSPSourceFactory ocspSourceFactoryMock = Mockito.mock(OCSPSourceFactory.class);
    Mockito.doReturn(sourceSpy).when(ocspSourceFactoryMock).create();
    configuration.setSigningOcspSourceFactory(ocspSourceFactoryMock);

    Signature signature = createSignatureBy(createNonEmptyContainerByConfiguration(), pkcs12SignatureToken);

    assertValidSignature(signature);
    Mockito.verify(ocspSourceFactoryMock, Mockito.times(1)).create();
    Mockito.verifyNoMoreInteractions(ocspSourceFactoryMock);
    Mockito.verify(sourceSpy, Mockito.atLeast(1))
            .getRevocationToken(any(CertificateToken.class), any(CertificateToken.class));
  }
}
