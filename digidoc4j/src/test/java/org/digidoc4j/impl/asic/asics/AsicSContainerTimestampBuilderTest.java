/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.asics;

import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import org.digidoc4j.CompositeContainer;
import org.digidoc4j.Configuration;
import org.digidoc4j.Constant;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.Timestamp;
import org.digidoc4j.TimestampBuilder;
import org.digidoc4j.X509Cert;
import org.digidoc4j.exceptions.IllegalContainerContentException;
import org.digidoc4j.impl.asic.AsicContainer;
import org.digidoc4j.impl.asic.asice.AsicEContainer;
import org.digidoc4j.impl.asic.asice.bdoc.BDocContainer;
import org.digidoc4j.impl.asic.cades.AbstractAsicContainerTimestampBuilderTest;
import org.digidoc4j.impl.ddoc.DDocContainer;
import org.digidoc4j.test.TestConstants;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;

import static org.digidoc4j.test.TestAssert.assertTimeBetweenNotBeforeAndNow;
import static org.digidoc4j.test.matcher.IsAsicArchiveManifestDataReference.isDataReferenceWithNameAndDigestAlgorithm;
import static org.digidoc4j.test.matcher.IsAsicArchiveManifestReference.isReferenceWithName;
import static org.digidoc4j.test.matcher.IsDssDocument.isDocumentWithMimeType;
import static org.digidoc4j.test.matcher.IsDssDocument.isDocumentWithName;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

public class AsicSContainerTimestampBuilderTest extends AbstractAsicContainerTimestampBuilderTest {

  @Test
  public void createInstance_WhenContainerIsAsicsContainer_Succeeds() {
    Container container = mock(AsicSContainer.class);

    AsicSContainerTimestampBuilder result = new AsicSContainerTimestampBuilder(container);

    assertThat(result.getContainer(), sameInstance(container));
    verifyNoInteractions(container);
  }

  @Test
  public void createInstance_WhenContainerIsGenericContainerType_ThrowsException() {
    createInstance_WhenContainerIsNotAsicsContainer_ThrowsException(Container.class);
  }

  @Test
  public void createInstance_WhenContainerIsGenericCompositeContainerType_ThrowsException() {
    createInstance_WhenContainerIsNotAsicsContainer_ThrowsException(CompositeContainer.class);
  }

  @Test
  public void createInstance_WhenContainerIsGenericAsicContainerType_ThrowsException() {
    createInstance_WhenContainerIsNotAsicsContainer_ThrowsException(AsicContainer.class);
  }

  @Test
  public void createInstance_WhenContainerIsAsiceContainerType_ThrowsException() {
    createInstance_WhenContainerIsNotAsicsContainer_ThrowsException(AsicEContainer.class);
  }

  @Test
  public void createInstance_WhenContainerIsBdocContainerType_ThrowsException() {
    createInstance_WhenContainerIsNotAsicsContainer_ThrowsException(BDocContainer.class);
  }

  @Test
  public void createInstance_WhenContainerIsDdocContainerType_ThrowsException() {
    createInstance_WhenContainerIsNotAsicsContainer_ThrowsException(DDocContainer.class);
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void createInstance_WhenContainerIsNotAsicsContainer_ThrowsException(Class<? extends Container> containerType) {
    Container container = mock(containerType);

    IllegalArgumentException caughtException = assertThrows(
            IllegalArgumentException.class,
            () -> new AsicSContainerTimestampBuilder(container)
    );

    assertThat(caughtException.getMessage(), equalTo("Not an ASiC-S container"));
    verifyNoInteractions(container);
  }

  @Test
  public void invokeTimestamping_WhenContainerHasSignatures_ThrowsIllegalContainerContentException() {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/valid-asics-esteid2018.asics",
            Configuration.of(Configuration.Mode.TEST)
    );
    TimestampBuilder timestampBuilder = TimestampBuilder.aTimestamp(container);

    IllegalContainerContentException caughtException = assertThrows(
            IllegalContainerContentException.class,
            timestampBuilder::invokeTimestamping
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("ASiC-S container containing signatures cannot be timestamped")
    );
  }

  @Test
  public void invokeTimestamping_WhenContainerHasMoreThanOneDataFile_ThrowsIllegalContainerContentException() {
    Container container = mock(AsicSContainer.class);
    doReturn(Constant.ASICS_CONTAINER_TYPE).when(container).getType();
    doReturn(Arrays.asList(
            createTextDataFile("1.txt", "First test file."),
            createTextDataFile("2.txt", "Second test file.")
    )).when(container).getDataFiles();
    TimestampBuilder timestampBuilder = TimestampBuilder.aTimestamp(container);

    IllegalContainerContentException caughtException = assertThrows(
            IllegalContainerContentException.class,
            timestampBuilder::invokeTimestamping
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("ASiC-S container must contain exactly one datafile to be timestamped")
    );
  }

  @Test
  public void invokeTimestamping_WhenContainerIsNotPreviouslyTimestamped_ReturnsValidTimestampWithoutManifest() {
    TimestampBuilder timestampBuilder = TimestampBuilder
            .aTimestamp(getDefaultContainerForTimestamping(Configuration.of(Configuration.Mode.TEST)));
    Instant notBefore = Instant.now();

    Timestamp result = timestampBuilder.invokeTimestamping();

    assertThat(result, notNullValue());
    assertThat(result, instanceOf(AsicSContainerTimestamp.class));
    assertTimeBetweenNotBeforeAndNow(result.getCreationTime(), notBefore, Duration.ofMinutes(1L));
    assertThat(result.getCertificate().getSubjectName(X509Cert.SubjectName.CN), equalTo(TestConstants.DEMO_TSA_CN));
    assertThat(result.getDigestAlgorithm(), sameInstance(DigestAlgorithm.SHA512));
    AsicSContainerTimestamp asicsTimestamp = (AsicSContainerTimestamp) result;
    assertThat(asicsTimestamp.getCadesTimestamp(), notNullValue());
    assertThat(asicsTimestamp.getCadesTimestamp().getTimestampDocument(), isDocumentWithName("META-INF/timestamp.tst"));
    assertThat(asicsTimestamp.getCadesTimestamp().getTimestampDocument(), isDocumentWithMimeType(MimeTypeEnum.TST));
    assertThat(asicsTimestamp.getArchiveManifest(), nullValue());
  }

  @Test
  public void invokeTimestamping_WhenContainerIsPreviouslyTimestamped_ReturnsValidTimestampWithManifest() {
    Container container = getDefaultContainerForTimestamping(Configuration.of(Configuration.Mode.TEST));
    container.addTimestamp(TimestampBuilder.aTimestamp(container).invokeTimestamping());
    TimestampBuilder timestampBuilder = TimestampBuilder.aTimestamp(container);
    Instant notBefore = Instant.now();

    Timestamp result = timestampBuilder.invokeTimestamping();

    assertThat(result, notNullValue());
    assertThat(result, instanceOf(AsicSContainerTimestamp.class));
    assertTimeBetweenNotBeforeAndNow(result.getCreationTime(), notBefore, Duration.ofMinutes(1L));
    assertThat(result.getCertificate().getSubjectName(X509Cert.SubjectName.CN), equalTo(TestConstants.DEMO_TSA_CN));
    assertThat(result.getDigestAlgorithm(), sameInstance(DigestAlgorithm.SHA512));
    AsicSContainerTimestamp asicsTimestamp = (AsicSContainerTimestamp) result;
    assertThat(asicsTimestamp.getCadesTimestamp(), notNullValue());
    assertThat(asicsTimestamp.getCadesTimestamp().getTimestampDocument(), isDocumentWithName("META-INF/timestamp002.tst"));
    assertThat(asicsTimestamp.getCadesTimestamp().getTimestampDocument(), isDocumentWithMimeType(MimeTypeEnum.TST));
    assertThat(asicsTimestamp.getArchiveManifest(), notNullValue());
    assertThat(asicsTimestamp.getArchiveManifest().getManifestDocument(), isDocumentWithName("META-INF/ASiCArchiveManifest.xml"));
    assertThat(asicsTimestamp.getArchiveManifest().getManifestDocument(), isDocumentWithMimeType(MimeTypeEnum.XML));
    assertThat(asicsTimestamp.getArchiveManifest().getReferencedTimestamp(), isReferenceWithName("META-INF/timestamp002.tst"));
    assertThat(asicsTimestamp.getArchiveManifest().getReferencedDataObjects(), containsInAnyOrder(
            isDataReferenceWithNameAndDigestAlgorithm("META-INF/timestamp.tst", DigestAlgorithm.SHA512),
            isDataReferenceWithNameAndDigestAlgorithm("test.txt", DigestAlgorithm.SHA512)
    ));
  }

  @Test
  public void invokeTimestamping_WhenParametersAreConfiguredViaConfiguration_ReturnsValid1stTimestampWithSha256() {
    invokeTimestamping_WhenParametersAreConfiguredViaConfiguration_ReturnsValid1stTimestampWithExpectedParameters(
            DigestAlgorithm.SHA256
    );
  }

  @Test
  public void invokeTimestamping_WhenParametersAreConfiguredViaConfiguration_ReturnsValid1stTimestampWithSha384() {
    invokeTimestamping_WhenParametersAreConfiguredViaConfiguration_ReturnsValid1stTimestampWithExpectedParameters(
            DigestAlgorithm.SHA384
    );
  }

  @Test
  public void invokeTimestamping_WhenParametersAreConfiguredViaConfiguration_ReturnsValid1stTimestampWithSha512() {
    invokeTimestamping_WhenParametersAreConfiguredViaConfiguration_ReturnsValid1stTimestampWithExpectedParameters(
            DigestAlgorithm.SHA512
    );
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void invokeTimestamping_WhenParametersAreConfiguredViaConfiguration_ReturnsValid1stTimestampWithExpectedParameters(
          DigestAlgorithm timestampDigestAlgorithm
  ) {
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);
    configuration.setTspSourceForArchiveTimestamps(TestConstants.DEMO_TSA_RSA_URL);
    configuration.setArchiveTimestampDigestAlgorithm(timestampDigestAlgorithm);
    TimestampBuilder timestampBuilder = TimestampBuilder
            .aTimestamp(getDefaultContainerForTimestamping(configuration));
    Instant notBefore = Instant.now();

    Timestamp result = timestampBuilder.invokeTimestamping();

    assertThat(result, notNullValue());
    assertThat(result, instanceOf(AsicSContainerTimestamp.class));
    assertTimeBetweenNotBeforeAndNow(result.getCreationTime(), notBefore, Duration.ofMinutes(1L));
    assertThat(result.getCertificate().getSubjectName(X509Cert.SubjectName.CN), equalTo(TestConstants.DEMO_TSA_RSA_CN));
    assertThat(result.getDigestAlgorithm(), sameInstance(timestampDigestAlgorithm));
    AsicSContainerTimestamp asicsTimestamp = (AsicSContainerTimestamp) result;
    assertThat(asicsTimestamp.getCadesTimestamp(), notNullValue());
    assertThat(asicsTimestamp.getCadesTimestamp().getTimestampDocument(), isDocumentWithName("META-INF/timestamp.tst"));
    assertThat(asicsTimestamp.getCadesTimestamp().getTimestampDocument(), isDocumentWithMimeType(MimeTypeEnum.TST));
    assertThat(asicsTimestamp.getArchiveManifest(), nullValue());
  }

  @Test
  public void invokeTimestamping_WhenParametersAreConfiguredViaConfiguration_ReturnsValid2ndTimestampWithBothSha256() {
    invokeTimestamping_WhenParametersAreConfiguredViaConfiguration_ReturnsValid2ndTimestampWithExpectedParameters(
            DigestAlgorithm.SHA256,
            DigestAlgorithm.SHA256
    );
  }

  @Test
  public void invokeTimestamping_WhenParametersAreConfiguredViaConfiguration_ReturnsValid2ndTimestampWithTstSha256AndRefSha384() {
    invokeTimestamping_WhenParametersAreConfiguredViaConfiguration_ReturnsValid2ndTimestampWithExpectedParameters(
            DigestAlgorithm.SHA256,
            DigestAlgorithm.SHA384
    );
  }

  @Test
  public void invokeTimestamping_WhenParametersAreConfiguredViaConfiguration_ReturnsValid2ndTimestampWithTstSha256AndRefSha512() {
    invokeTimestamping_WhenParametersAreConfiguredViaConfiguration_ReturnsValid2ndTimestampWithExpectedParameters(
            DigestAlgorithm.SHA256,
            DigestAlgorithm.SHA512
    );
  }

  @Test
  public void invokeTimestamping_WhenParametersAreConfiguredViaConfiguration_ReturnsValid2ndTimestampWithTstSha384AndRefSha256() {
    invokeTimestamping_WhenParametersAreConfiguredViaConfiguration_ReturnsValid2ndTimestampWithExpectedParameters(
            DigestAlgorithm.SHA384,
            DigestAlgorithm.SHA256
    );
  }

  @Test
  public void invokeTimestamping_WhenParametersAreConfiguredViaConfiguration_ReturnsValid2ndTimestampWithBothSha384() {
    invokeTimestamping_WhenParametersAreConfiguredViaConfiguration_ReturnsValid2ndTimestampWithExpectedParameters(
            DigestAlgorithm.SHA384,
            DigestAlgorithm.SHA384
    );
  }

  @Test
  public void invokeTimestamping_WhenParametersAreConfiguredViaConfiguration_ReturnsValid2ndTimestampWithTstSha384AndRefSha512() {
    invokeTimestamping_WhenParametersAreConfiguredViaConfiguration_ReturnsValid2ndTimestampWithExpectedParameters(
            DigestAlgorithm.SHA384,
            DigestAlgorithm.SHA512
    );
  }

  @Test
  public void invokeTimestamping_WhenParametersAreConfiguredViaConfiguration_ReturnsValid2ndTimestampWithTstSha512AndRefSha256() {
    invokeTimestamping_WhenParametersAreConfiguredViaConfiguration_ReturnsValid2ndTimestampWithExpectedParameters(
            DigestAlgorithm.SHA512,
            DigestAlgorithm.SHA256
    );
  }

  @Test
  public void invokeTimestamping_WhenParametersAreConfiguredViaConfiguration_ReturnsValid2ndTimestampWithTstSha512AndRefSha384() {
    invokeTimestamping_WhenParametersAreConfiguredViaConfiguration_ReturnsValid2ndTimestampWithExpectedParameters(
            DigestAlgorithm.SHA512,
            DigestAlgorithm.SHA384
    );
  }

  @Test
  public void invokeTimestamping_WhenParametersAreConfiguredViaConfiguration_ReturnsValid2ndTimestampWithBothSha512() {
    invokeTimestamping_WhenParametersAreConfiguredViaConfiguration_ReturnsValid2ndTimestampWithExpectedParameters(
            DigestAlgorithm.SHA512,
            DigestAlgorithm.SHA512
    );
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void invokeTimestamping_WhenParametersAreConfiguredViaConfiguration_ReturnsValid2ndTimestampWithExpectedParameters(
          DigestAlgorithm timestampDigestAlgorithm,
          DigestAlgorithm referenceDigestAlgorithm
  ) {
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);
    Container container = getDefaultContainerForTimestamping(configuration);
    container.addTimestamp(TimestampBuilder.aTimestamp(container).invokeTimestamping());
    configuration.setTspSourceForArchiveTimestamps(TestConstants.DEMO_TSA_RSA_URL);
    configuration.setArchiveTimestampDigestAlgorithm(timestampDigestAlgorithm);
    configuration.setArchiveTimestampReferenceDigestAlgorithm(referenceDigestAlgorithm);
    TimestampBuilder timestampBuilder = TimestampBuilder.aTimestamp(container);
    Instant notBefore = Instant.now();

    Timestamp result = timestampBuilder.invokeTimestamping();

    assertThat(result, notNullValue());
    assertThat(result, instanceOf(AsicSContainerTimestamp.class));
    assertTimeBetweenNotBeforeAndNow(result.getCreationTime(), notBefore, Duration.ofMinutes(1L));
    assertThat(result.getCertificate().getSubjectName(X509Cert.SubjectName.CN), equalTo(TestConstants.DEMO_TSA_RSA_CN));
    assertThat(result.getDigestAlgorithm(), sameInstance(timestampDigestAlgorithm));
    AsicSContainerTimestamp asicsTimestamp = (AsicSContainerTimestamp) result;
    assertThat(asicsTimestamp.getCadesTimestamp(), notNullValue());
    assertThat(asicsTimestamp.getCadesTimestamp().getTimestampDocument(), isDocumentWithName("META-INF/timestamp002.tst"));
    assertThat(asicsTimestamp.getCadesTimestamp().getTimestampDocument(), isDocumentWithMimeType(MimeTypeEnum.TST));
    assertThat(asicsTimestamp.getArchiveManifest(), notNullValue());
    assertThat(asicsTimestamp.getArchiveManifest().getManifestDocument(), isDocumentWithName("META-INF/ASiCArchiveManifest.xml"));
    assertThat(asicsTimestamp.getArchiveManifest().getManifestDocument(), isDocumentWithMimeType(MimeTypeEnum.XML));
    assertThat(asicsTimestamp.getArchiveManifest().getReferencedTimestamp(), isReferenceWithName("META-INF/timestamp002.tst"));
    assertThat(asicsTimestamp.getArchiveManifest().getReferencedDataObjects(), containsInAnyOrder(
            isDataReferenceWithNameAndDigestAlgorithm("META-INF/timestamp.tst", referenceDigestAlgorithm),
            isDataReferenceWithNameAndDigestAlgorithm("test.txt", referenceDigestAlgorithm)
    ));
  }

  @Test
  public void invokeTimestamping_WhenParametersAreConfiguredViaTimestampBuilder_ReturnsValid1stTimestampWithSha256() {
    invokeTimestamping_WhenParametersAreConfiguredViaTimestampBuilder_ReturnsValid1stTimestampWithExpectedParameters(
            DigestAlgorithm.SHA256
    );
  }

  @Test
  public void invokeTimestamping_WhenParametersAreConfiguredViaTimestampBuilder_ReturnsValid1stTimestampWithSha384() {
    invokeTimestamping_WhenParametersAreConfiguredViaTimestampBuilder_ReturnsValid1stTimestampWithExpectedParameters(
            DigestAlgorithm.SHA384
    );
  }

  @Test
  public void invokeTimestamping_WhenParametersAreConfiguredViaTimestampBuilder_ReturnsValid1stTimestampWithSha512() {
    invokeTimestamping_WhenParametersAreConfiguredViaTimestampBuilder_ReturnsValid1stTimestampWithExpectedParameters(
            DigestAlgorithm.SHA512
    );
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void invokeTimestamping_WhenParametersAreConfiguredViaTimestampBuilder_ReturnsValid1stTimestampWithExpectedParameters(
          DigestAlgorithm timestampDigestAlgorithm
  ) {
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);
    TimestampBuilder timestampBuilder = TimestampBuilder
            .aTimestamp(getDefaultContainerForTimestamping(configuration))
            .withTimestampDigestAlgorithm(timestampDigestAlgorithm)
            .withTspSource(TestConstants.DEMO_TSA_RSA_URL);
    Instant notBefore = Instant.now();

    Timestamp result = timestampBuilder.invokeTimestamping();

    assertThat(result, notNullValue());
    assertThat(result, instanceOf(AsicSContainerTimestamp.class));
    assertTimeBetweenNotBeforeAndNow(result.getCreationTime(), notBefore, Duration.ofMinutes(1L));
    assertThat(result.getCertificate().getSubjectName(X509Cert.SubjectName.CN), equalTo(TestConstants.DEMO_TSA_RSA_CN));
    assertThat(result.getDigestAlgorithm(), sameInstance(timestampDigestAlgorithm));
    AsicSContainerTimestamp asicsTimestamp = (AsicSContainerTimestamp) result;
    assertThat(asicsTimestamp.getCadesTimestamp(), notNullValue());
    assertThat(asicsTimestamp.getCadesTimestamp().getTimestampDocument(), isDocumentWithName("META-INF/timestamp.tst"));
    assertThat(asicsTimestamp.getCadesTimestamp().getTimestampDocument(), isDocumentWithMimeType(MimeTypeEnum.TST));
    assertThat(asicsTimestamp.getArchiveManifest(), nullValue());
  }

  @Test
  public void invokeTimestamping_WhenParametersAreConfiguredViaTimestampBuilder_ReturnsValid2ndTimestampWithBothSha256() {
    invokeTimestamping_WhenParametersAreConfiguredViaTimestampBuilder_ReturnsValid2ndTimestampWithExpectedParameters(
            DigestAlgorithm.SHA256,
            DigestAlgorithm.SHA256
    );
  }

  @Test
  public void invokeTimestamping_WhenParametersAreConfiguredViaTimestampBuilder_ReturnsValid2ndTimestampWithTstSha256AndRefSha384() {
    invokeTimestamping_WhenParametersAreConfiguredViaTimestampBuilder_ReturnsValid2ndTimestampWithExpectedParameters(
            DigestAlgorithm.SHA256,
            DigestAlgorithm.SHA384
    );
  }

  @Test
  public void invokeTimestamping_WhenParametersAreConfiguredViaTimestampBuilder_ReturnsValid2ndTimestampWithTstSha256AndRefSha512() {
    invokeTimestamping_WhenParametersAreConfiguredViaTimestampBuilder_ReturnsValid2ndTimestampWithExpectedParameters(
            DigestAlgorithm.SHA256,
            DigestAlgorithm.SHA512
    );
  }

  @Test
  public void invokeTimestamping_WhenParametersAreConfiguredViaTimestampBuilder_ReturnsValid2ndTimestampWithTstSha384AndRefSha256() {
    invokeTimestamping_WhenParametersAreConfiguredViaTimestampBuilder_ReturnsValid2ndTimestampWithExpectedParameters(
            DigestAlgorithm.SHA384,
            DigestAlgorithm.SHA256
    );
  }

  @Test
  public void invokeTimestamping_WhenParametersAreConfiguredViaTimestampBuilder_ReturnsValid2ndTimestampWithBothSha384() {
    invokeTimestamping_WhenParametersAreConfiguredViaTimestampBuilder_ReturnsValid2ndTimestampWithExpectedParameters(
            DigestAlgorithm.SHA384,
            DigestAlgorithm.SHA384
    );
  }

  @Test
  public void invokeTimestamping_WhenParametersAreConfiguredViaTimestampBuilder_ReturnsValid2ndTimestampWithTstSha384AndRefSha512() {
    invokeTimestamping_WhenParametersAreConfiguredViaTimestampBuilder_ReturnsValid2ndTimestampWithExpectedParameters(
            DigestAlgorithm.SHA384,
            DigestAlgorithm.SHA512
    );
  }

  @Test
  public void invokeTimestamping_WhenParametersAreConfiguredViaTimestampBuilder_ReturnsValid2ndTimestampWithTstSha512AndRefSha256() {
    invokeTimestamping_WhenParametersAreConfiguredViaTimestampBuilder_ReturnsValid2ndTimestampWithExpectedParameters(
            DigestAlgorithm.SHA512,
            DigestAlgorithm.SHA256
    );
  }

  @Test
  public void invokeTimestamping_WhenParametersAreConfiguredViaTimestampBuilder_ReturnsValid2ndTimestampWithTstSha512AndRefSha384() {
    invokeTimestamping_WhenParametersAreConfiguredViaTimestampBuilder_ReturnsValid2ndTimestampWithExpectedParameters(
            DigestAlgorithm.SHA512,
            DigestAlgorithm.SHA384
    );
  }

  @Test
  public void invokeTimestamping_WhenParametersAreConfiguredViaTimestampBuilder_ReturnsValid2ndTimestampWithBothSha512() {
    invokeTimestamping_WhenParametersAreConfiguredViaTimestampBuilder_ReturnsValid2ndTimestampWithExpectedParameters(
            DigestAlgorithm.SHA512,
            DigestAlgorithm.SHA512
    );
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void invokeTimestamping_WhenParametersAreConfiguredViaTimestampBuilder_ReturnsValid2ndTimestampWithExpectedParameters(
          DigestAlgorithm timestampDigestAlgorithm,
          DigestAlgorithm referenceDigestAlgorithm
  ) {
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);
    Container container = getDefaultContainerForTimestamping(configuration);
    container.addTimestamp(TimestampBuilder.aTimestamp(container).invokeTimestamping());
    TimestampBuilder timestampBuilder = TimestampBuilder.aTimestamp(container)
            .withTimestampDigestAlgorithm(timestampDigestAlgorithm)
            .withReferenceDigestAlgorithm(referenceDigestAlgorithm)
            .withTspSource(TestConstants.DEMO_TSA_RSA_URL);
    Instant notBefore = Instant.now();

    Timestamp result = timestampBuilder.invokeTimestamping();

    assertThat(result, notNullValue());
    assertThat(result, instanceOf(AsicSContainerTimestamp.class));
    assertTimeBetweenNotBeforeAndNow(result.getCreationTime(), notBefore, Duration.ofMinutes(1L));
    assertThat(result.getCertificate().getSubjectName(X509Cert.SubjectName.CN), equalTo(TestConstants.DEMO_TSA_RSA_CN));
    assertThat(result.getDigestAlgorithm(), sameInstance(timestampDigestAlgorithm));
    AsicSContainerTimestamp asicsTimestamp = (AsicSContainerTimestamp) result;
    assertThat(asicsTimestamp.getCadesTimestamp(), notNullValue());
    assertThat(asicsTimestamp.getCadesTimestamp().getTimestampDocument(), isDocumentWithName("META-INF/timestamp002.tst"));
    assertThat(asicsTimestamp.getCadesTimestamp().getTimestampDocument(), isDocumentWithMimeType(MimeTypeEnum.TST));
    assertThat(asicsTimestamp.getArchiveManifest(), notNullValue());
    assertThat(asicsTimestamp.getArchiveManifest().getManifestDocument(), isDocumentWithName("META-INF/ASiCArchiveManifest.xml"));
    assertThat(asicsTimestamp.getArchiveManifest().getManifestDocument(), isDocumentWithMimeType(MimeTypeEnum.XML));
    assertThat(asicsTimestamp.getArchiveManifest().getReferencedTimestamp(), isReferenceWithName("META-INF/timestamp002.tst"));
    assertThat(asicsTimestamp.getArchiveManifest().getReferencedDataObjects(), containsInAnyOrder(
            isDataReferenceWithNameAndDigestAlgorithm("META-INF/timestamp.tst", referenceDigestAlgorithm),
            isDataReferenceWithNameAndDigestAlgorithm("test.txt", referenceDigestAlgorithm)
    ));
  }

  @Override
  protected Container getDefaultContainerForTimestamping(Configuration configuration) {
    return ContainerBuilder
            .aContainer(Container.DocumentType.ASICS)
            .withConfiguration(configuration)
            .withDataFile(createTextDataFile("test.txt", "This is a test file."))
            .build();
  }

  @Override
  protected Container getEmptyContainerForTimestamping(Configuration configuration) {
    return ContainerBuilder
            .aContainer(Container.DocumentType.ASICS)
            .withConfiguration(configuration)
            .build();
  }

}
