/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.cades;

import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import org.apache.commons.codec.binary.Base64;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.X509Cert;
import org.digidoc4j.test.TestConstants;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;

import static org.digidoc4j.test.matcher.CommonMatchers.equalToIsoDate;
import static org.digidoc4j.test.matcher.IsAsicArchiveManifestDataReference.isDataReferenceWithDigestValue;
import static org.digidoc4j.test.matcher.IsAsicArchiveManifestDataReference.isDataReferenceWithNameAndMimeTypeAndDigestAlgorithm;
import static org.digidoc4j.test.matcher.IsAsicArchiveManifestReference.isReferenceWithNameAndMimeType;
import static org.digidoc4j.test.matcher.IsDssDocument.isDocumentWithNameAndMimeType;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

public class CadesTimestampingDssFacadeTest extends AbstractCadesDssFacadeTest<CadesTimestampingDssFacade> {

  @Test
  public void timestampContent_WhenNoExistingTimestampsSpecifiedAndUsingEccTimestampWithSha256TimestampDigestAlgorithm_ReturnsTimestampWithExpectedParameters() {
    timestampContent_WhenNoExistingTimestampsSpecified_ReturnsTimestampWithExpectedParametersAndWithoutManifest(
            DigestAlgorithm.SHA256,
            TestConstants.DEMO_TSA_ECC_URL,
            TestConstants.DEMO_TSA_ECC_CN
    );
  }

  @Test
  public void timestampContent_WhenNoExistingTimestampsSpecifiedAndUsingRsaTimestampWithSha256TimestampDigestAlgorithm_ReturnsTimestampWithExpectedParameters() {
    timestampContent_WhenNoExistingTimestampsSpecified_ReturnsTimestampWithExpectedParametersAndWithoutManifest(
            DigestAlgorithm.SHA256,
            TestConstants.DEMO_TSA_RSA_URL,
            TestConstants.DEMO_TSA_RSA_CN
    );
  }

  @Test
  public void timestampContent_WhenNoExistingTimestampsSpecifiedAndUsingEccTimestampWithSha384TimestampDigestAlgorithm_ReturnsTimestampWithExpectedParameters() {
    timestampContent_WhenNoExistingTimestampsSpecified_ReturnsTimestampWithExpectedParametersAndWithoutManifest(
            DigestAlgorithm.SHA384,
            TestConstants.DEMO_TSA_ECC_URL,
            TestConstants.DEMO_TSA_ECC_CN
    );
  }

  @Test
  public void timestampContent_WhenNoExistingTimestampsSpecifiedAndUsingRsaTimestampWithSha384TimestampDigestAlgorithm_ReturnsTimestampWithExpectedParameters() {
    timestampContent_WhenNoExistingTimestampsSpecified_ReturnsTimestampWithExpectedParametersAndWithoutManifest(
            DigestAlgorithm.SHA384,
            TestConstants.DEMO_TSA_RSA_URL,
            TestConstants.DEMO_TSA_RSA_CN
    );
  }

  @Test
  public void timestampContent_WhenNoExistingTimestampsSpecifiedAndUsingEccTimestampWithSha512TimestampDigestAlgorithm_ReturnsTimestampWithExpectedParameters() {
    timestampContent_WhenNoExistingTimestampsSpecified_ReturnsTimestampWithExpectedParametersAndWithoutManifest(
            DigestAlgorithm.SHA512,
            TestConstants.DEMO_TSA_ECC_URL,
            TestConstants.DEMO_TSA_ECC_CN
    );
  }

  @Test
  public void timestampContent_WhenNoExistingTimestampsSpecifiedAndUsingRsaTimestampWithSha512TimestampDigestAlgorithm_ReturnsTimestampWithExpectedParameters() {
    timestampContent_WhenNoExistingTimestampsSpecified_ReturnsTimestampWithExpectedParametersAndWithoutManifest(
            DigestAlgorithm.SHA512,
            TestConstants.DEMO_TSA_RSA_URL,
            TestConstants.DEMO_TSA_RSA_CN
    );
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void timestampContent_WhenNoExistingTimestampsSpecified_ReturnsTimestampWithExpectedParametersAndWithoutManifest(
          DigestAlgorithm timestampDigestAlgorithm,
          String timestampServiceUrl,
          String expectedTimestampCn
  ) {
    CadesTimestampingDssFacade cadesTimestampingDssFacade = getDefaultCadesDssFacade();
    cadesTimestampingDssFacade.setContainerType(Container.DocumentType.ASICS);
    cadesTimestampingDssFacade.setTspSource(new OnlineTSPSource(timestampServiceUrl));
    cadesTimestampingDssFacade.setTimestampDigestAlgorithm(timestampDigestAlgorithm);
    DSSDocument dataFile = new InMemoryDocument(
            "This is a test file.".getBytes(StandardCharsets.UTF_8),
            "test.txt",
            MimeTypeEnum.TEXT
    );
    List<DSSDocument> dataFiles = Collections.singletonList(dataFile);

    TimestampDocumentsHolder result = cadesTimestampingDssFacade.timestampContent(dataFiles, Collections.emptyList());

    assertThat(result, notNullValue());
    assertThat(result.getTimestampDocument(), notNullValue());
    assertThat(result.getTimestampDocument(), isDocumentWithNameAndMimeType("META-INF/timestamp.tst", MimeTypeEnum.TST));
    {
      CadesTimestamp cadesTimestamp = new CadesTimestamp(result.getTimestampDocument());
      assertThat(cadesTimestamp.getCertificate().getSubjectName(X509Cert.SubjectName.CN), equalTo(expectedTimestampCn));
      assertThat(
              cadesTimestamp.getTimeStampToken().getTimeStampInfo().getMessageImprintAlgOID().toString(),
              equalTo(timestampDigestAlgorithm.getDssDigestAlgorithm().getOid())
      );
      assertThat(
              cadesTimestamp.getTimeStampToken().getTimeStampInfo().getMessageImprintDigest(),
              is(Base64.decodeBase64(dataFile.getDigest(timestampDigestAlgorithm.getDssDigestAlgorithm())))
      );
    }
    assertThat(result.getManifestDocument(), nullValue());
  }

  @Test
  public void timestampContent_WhenTwoExistingTimestampsSpecifiedAndUsingEccTimestampWithSha256ReferenceDigestAlgorithm_ReturnsTimestampWithExpectedParametersAndManifest() {
    timestampContent_WhenTwoExistingTimestampsSpecified_ReturnsTimestampWithExpectedParametersAndManifest(
            DigestAlgorithm.SHA256,
            TestConstants.DEMO_TSA_ECC_URL,
            TestConstants.DEMO_TSA_ECC_CN
    );
  }

  @Test
  public void timestampContent_WhenTwoExistingTimestampsSpecifiedAndUsingRsaTimestampWithSha256ReferenceDigestAlgorithm_ReturnsTimestampWithExpectedParametersAndManifest() {
    timestampContent_WhenTwoExistingTimestampsSpecified_ReturnsTimestampWithExpectedParametersAndManifest(
            DigestAlgorithm.SHA256,
            TestConstants.DEMO_TSA_RSA_URL,
            TestConstants.DEMO_TSA_RSA_CN
    );
  }

  @Test
  public void timestampContent_WhenTwoExistingTimestampsSpecifiedAndUsingEccTimestampWithSha384ReferenceDigestAlgorithm_ReturnsTimestampWithExpectedParametersAndManifest() {
    timestampContent_WhenTwoExistingTimestampsSpecified_ReturnsTimestampWithExpectedParametersAndManifest(
            DigestAlgorithm.SHA384,
            TestConstants.DEMO_TSA_ECC_URL,
            TestConstants.DEMO_TSA_ECC_CN
    );
  }

  @Test
  public void timestampContent_WhenTwoExistingTimestampsSpecifiedAndUsingRsaTimestampWithSha384ReferenceDigestAlgorithm_ReturnsTimestampWithExpectedParametersAndManifest() {
    timestampContent_WhenTwoExistingTimestampsSpecified_ReturnsTimestampWithExpectedParametersAndManifest(
            DigestAlgorithm.SHA384,
            TestConstants.DEMO_TSA_RSA_URL,
            TestConstants.DEMO_TSA_RSA_CN
    );
  }

  @Test
  public void timestampContent_WhenTwoExistingTimestampsSpecifiedAndUsingEccTimestampWithSha512ReferenceDigestAlgorithm_ReturnsTimestampWithExpectedParametersAndManifest() {
    timestampContent_WhenTwoExistingTimestampsSpecified_ReturnsTimestampWithExpectedParametersAndManifest(
            DigestAlgorithm.SHA512,
            TestConstants.DEMO_TSA_ECC_URL,
            TestConstants.DEMO_TSA_ECC_CN
    );
  }

  @Test
  public void timestampContent_WhenTwoExistingTimestampsSpecifiedAndUsingRsaTimestampWithSha512ReferenceDigestAlgorithm_ReturnsTimestampWithExpectedParametersAndManifest() {
    timestampContent_WhenTwoExistingTimestampsSpecified_ReturnsTimestampWithExpectedParametersAndManifest(
            DigestAlgorithm.SHA512,
            TestConstants.DEMO_TSA_RSA_URL,
            TestConstants.DEMO_TSA_RSA_CN
    );
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void timestampContent_WhenTwoExistingTimestampsSpecified_ReturnsTimestampWithExpectedParametersAndManifest(
          DigestAlgorithm referenceDigestAlgorithm,
          String timestampServiceUrl,
          String expectedTimestampCn
  ) {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/2xTST-text-data-file.asics",
            configuration
    );
    CadesTimestampingDssFacade cadesTimestampingDssFacade = getDefaultCadesDssFacade();
    cadesTimestampingDssFacade.setContainerType(Container.DocumentType.ASICS);
    cadesTimestampingDssFacade.setTspSource(new OnlineTSPSource(timestampServiceUrl));
    cadesTimestampingDssFacade.setTimestampDigestAlgorithm(DigestAlgorithm.SHA256);
    cadesTimestampingDssFacade.setReferenceDigestAlgorithm(referenceDigestAlgorithm);
    DSSDocument dataFile = container.getDataFiles().get(0).getDocument();
    List<DSSDocument> dataFiles = Collections.singletonList(dataFile);
    TimestampAndManifestPair timestamp0 = (TimestampAndManifestPair) container.getTimestamps().get(0);
    UpdateableTimestampDocumentsHolder timestampDocuments0 = createTimestampDocumentsHolder(timestamp0);
    @SuppressWarnings("unchecked") Consumer<DSSDocument> timestampOverrideListener0 = mock(Consumer.class);
    timestampDocuments0.setTimestampDocumentOverrideListener(timestampOverrideListener0);
    TimestampAndManifestPair timestamp1 = (TimestampAndManifestPair) container.getTimestamps().get(1);
    UpdateableTimestampDocumentsHolder timestampDocuments1 = createTimestampDocumentsHolder(timestamp1);
    @SuppressWarnings("unchecked") Consumer<DSSDocument> timestampOverrideListener1 = mock(Consumer.class);
    timestampDocuments1.setTimestampDocumentOverrideListener(timestampOverrideListener1);
    List<UpdateableTimestampDocumentsHolder> existingTimestamps = Collections.unmodifiableList(
            Arrays.asList(timestampDocuments0, timestampDocuments1)
    );

    TimestampDocumentsHolder result = cadesTimestampingDssFacade.timestampContent(dataFiles, existingTimestamps);

    verifyNoInteractions(timestampOverrideListener0);
    ArgumentCaptor<DSSDocument> dssDocumentArgumentCaptor = ArgumentCaptor.forClass(DSSDocument.class);
    verify(timestampOverrideListener1).accept(dssDocumentArgumentCaptor.capture());
    DSSDocument capturedDocument = dssDocumentArgumentCaptor.getValue();
    assertThat(capturedDocument, isDocumentWithNameAndMimeType("META-INF/timestamp002.tst", MimeTypeEnum.TST));
    verifyNoMoreInteractions(timestampOverrideListener1);
    {
      CadesTimestamp modifiedCadesTimestamp = new CadesTimestamp(capturedDocument);
      assertThat(modifiedCadesTimestamp.getCreationTime(), equalToIsoDate("2024-05-28T12:40:15Z"));
      assertThat(
              modifiedCadesTimestamp.getCertificate().getSubjectName(X509Cert.SubjectName.CN),
              equalTo(TestConstants.DEMO_SK_TSA_2023E_CN)
      );
      assertThat(
              modifiedCadesTimestamp.getTimeStampToken().getTimeStampInfo().getMessageImprintAlgOID().toString(),
              equalTo(DigestAlgorithm.SHA384.getDssDigestAlgorithm().getOid())
      );
      assertThat(
              modifiedCadesTimestamp.getTimeStampToken().getTimeStampInfo().getMessageImprintDigest(),
              is(Base64.decodeBase64("Gxq6WZ8Xvcj/nJx2ufNc2QXdEHtcDwapS5XwKaPaTrifjSPENk21PlpuMQdYB86+"))
      );
    }
    assertThat(result, notNullValue());
    assertThat(result.getTimestampDocument(), notNullValue());
    assertThat(result.getTimestampDocument(), isDocumentWithNameAndMimeType("META-INF/timestamp003.tst", MimeTypeEnum.TST));
    assertThat(result.getManifestDocument(), notNullValue());
    {
      CadesTimestamp newCadesTimestamp = new CadesTimestamp(result.getTimestampDocument());
      assertThat(newCadesTimestamp.getCertificate().getSubjectName(X509Cert.SubjectName.CN), equalTo(expectedTimestampCn));
      assertThat(
              newCadesTimestamp.getTimeStampToken().getTimeStampInfo().getMessageImprintAlgOID().toString(),
              equalTo(DigestAlgorithm.SHA256.getDssDigestAlgorithm().getOid())
      );
      assertThat(
              newCadesTimestamp.getTimeStampToken().getTimeStampInfo().getMessageImprintDigest(),
              is(Base64.decodeBase64(result.getManifestDocument().getDigest(DigestAlgorithm.SHA256.getDssDigestAlgorithm())))
      );
    }
    assertThat(result.getManifestDocument(), isDocumentWithNameAndMimeType("META-INF/ASiCArchiveManifest.xml", MimeTypeEnum.XML));
    {
      AsicArchiveManifest archiveManifest = new AsicArchiveManifest(result.getManifestDocument());
      assertThat(archiveManifest.getReferencedTimestamp(), isReferenceWithNameAndMimeType("META-INF/timestamp003.tst", MimeTypeEnum.TST));
      eu.europa.esig.dss.enumerations.DigestAlgorithm referenceDssDigestAlgorithm = referenceDigestAlgorithm.getDssDigestAlgorithm();
      assertThat(archiveManifest.getReferencedDataObjects(), contains(
              allOf(
                      isDataReferenceWithNameAndMimeTypeAndDigestAlgorithm("META-INF/timestamp.tst", MimeTypeEnum.TST, referenceDigestAlgorithm),
                      isDataReferenceWithDigestValue(timestamp0.getCadesTimestamp().getTimestampDocument().getDigest(referenceDssDigestAlgorithm))
              ),
              allOf(
                      isDataReferenceWithNameAndMimeTypeAndDigestAlgorithm("META-INF/timestamp002.tst", MimeTypeEnum.TST, referenceDigestAlgorithm),
                      isDataReferenceWithDigestValue(capturedDocument.getDigest(referenceDssDigestAlgorithm))
              ),
              allOf(
                      isDataReferenceWithNameAndMimeTypeAndDigestAlgorithm("META-INF/ASiCArchiveManifest001.xml", MimeTypeEnum.XML, referenceDigestAlgorithm),
                      isDataReferenceWithDigestValue(timestamp1.getArchiveManifest().getManifestDocument().getDigest(referenceDssDigestAlgorithm))
              ),
              allOf(
                      isDataReferenceWithNameAndMimeTypeAndDigestAlgorithm("test.txt", MimeTypeEnum.TEXT, referenceDigestAlgorithm),
                      isDataReferenceWithDigestValue(dataFile.getDigest(referenceDssDigestAlgorithm))
              )
      ));
    }
  }

  private static UpdateableTimestampDocumentsHolder createTimestampDocumentsHolder(TimestampAndManifestPair timestamp) {
    UpdateableTimestampDocumentsHolder documentsHolder = new UpdateableTimestampDocumentsHolder();
    documentsHolder.setTimestampDocument(timestamp.getCadesTimestamp().getTimestampDocument());
    if (timestamp.getArchiveManifest() != null) {
      documentsHolder.setManifestDocument(timestamp.getArchiveManifest().getManifestDocument());
    }
    return documentsHolder;
  }

  @Override
  protected CadesTimestampingDssFacade getDefaultCadesDssFacade() {
    CadesTimestampingDssFacade cadesTimestampingDssFacade = new CadesTimestampingDssFacade();
    configureAiaSourceAndCertificateSource(cadesTimestampingDssFacade);
    cadesTimestampingDssFacade.setOcspSource(new OnlineOCSPSource());
    return cadesTimestampingDssFacade;
  }

}
