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
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import static org.digidoc4j.test.TestAssert.assertTimeBetweenNotBeforeAndNow;
import static org.digidoc4j.test.matcher.IsAsicArchiveManifestDataReference.isDataReferenceWithNameAndDigestAlgorithm;
import static org.digidoc4j.test.matcher.IsAsicArchiveManifestReference.isReferenceWithName;
import static org.digidoc4j.test.matcher.IsDssDocument.isDocumentWithMimeType;
import static org.digidoc4j.test.matcher.IsDssDocument.isDocumentWithName;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

class AsicSContainerTimestampBuilderTest extends AbstractAsicContainerTimestampBuilderTest {

  @Test
  void createInstance_WhenContainerIsAsicsContainer_Succeeds() {
    Container container = mock(AsicSContainer.class);

    AsicSContainerTimestampBuilder result = new AsicSContainerTimestampBuilder(container);

    assertThat(result.getContainer(), sameInstance(container));
    verifyNoInteractions(container);
  }

  @ParameterizedTest
  @MethodSource("notAsicsContainerTypes")
  void createInstance_WhenContainerIsNotAsicsContainer_ThrowsException(Class<? extends Container> containerType) {
    Container container = mock(containerType);

    IllegalArgumentException caughtException = assertThrows(
            IllegalArgumentException.class,
            () -> new AsicSContainerTimestampBuilder(container)
    );

    assertThat(caughtException.getMessage(), equalTo("Not an ASiC-S container"));
    verifyNoInteractions(container);
  }

  private static Stream<Class<? extends Container>> notAsicsContainerTypes() {
    return Stream.of(
            Container.class,
            CompositeContainer.class,
            AsicContainer.class,
            AsicEContainer.class,
            BDocContainer.class,
            DDocContainer.class
    );
  }

  @Test
  void invokeTimestamping_WhenContainerHasSignatures_ThrowsIllegalContainerContentException() {
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
  void invokeTimestamping_WhenContainerHasMoreThanOneDataFile_ThrowsIllegalContainerContentException() {
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
  void invokeTimestamping_WhenContainerIsNotPreviouslyTimestamped_ReturnsValidTimestampWithoutManifest() {
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
  void invokeTimestamping_WhenContainerIsPreviouslyTimestamped_ReturnsValidTimestampWithManifest() {
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

  @ParameterizedTest
  @EnumSource(
          value = DigestAlgorithm.class,
          names = {"SHA256", "SHA384", "SHA512"}
  )
  void invokeTimestamping_WhenParametersAreConfiguredViaConfiguration_ReturnsValid1stTimestampWithExpectedParameters(
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

  @ParameterizedTest
  @MethodSource("supportedDigestAlgorithms")
  void invokeTimestamping_WhenParametersAreConfiguredViaConfiguration_ReturnsValid2ndTimestampWithExpectedParameters(
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

  @ParameterizedTest
  @EnumSource(
          value = DigestAlgorithm.class,
          names = {"SHA256", "SHA384", "SHA512"}
  )
  void invokeTimestamping_WhenParametersAreConfiguredViaTimestampBuilder_ReturnsValid1stTimestampWithExpectedParameters(
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

  @ParameterizedTest
  @MethodSource("supportedDigestAlgorithms")
  void invokeTimestamping_WhenParametersAreConfiguredViaTimestampBuilder_ReturnsValid2ndTimestampWithExpectedParameters(
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

  @ParameterizedTest
  @EnumSource(value = DigestAlgorithm.class,
              names = {"SHA3_256", "SHA3_384", "SHA3_512"})
  void invokeTimestamping_WhenConfigurationUsesSha3TimestampDigestFor1stTimestamp_ThrowsTsaRejection(
          DigestAlgorithm tsaRejectedTimestampDigest
  ) {
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);
    configuration.setTspSourceForArchiveTimestamps(TestConstants.DEMO_TSA_RSA_URL);
    configuration.setArchiveTimestampDigestAlgorithm(tsaRejectedTimestampDigest);
    configuration.setArchiveTimestampReferenceDigestAlgorithm(DigestAlgorithm.SHA256);

    Container container = getDefaultContainerForTimestamping(configuration);
    TimestampBuilder timestampBuilder = TimestampBuilder.aTimestamp(container);

    assertTimestampDigestRejectedByConfiguredTsa(timestampBuilder);
  }

  @ParameterizedTest
  @EnumSource(value = DigestAlgorithm.class,
              names = {"SHA3_256", "SHA3_384", "SHA3_512"})
  void invokeTimestamping_WhenConfigurationUsesSha3TimestampDigestFor2ndTimestamp_ThrowsTsaRejection(
          DigestAlgorithm tsaRejectedTimestampDigest
  ) {
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);
    Container container = getDefaultContainerForTimestamping(configuration);
    container.addTimestamp(TimestampBuilder.aTimestamp(container).invokeTimestamping());

    configuration.setTspSourceForArchiveTimestamps(TestConstants.DEMO_TSA_RSA_URL);
    configuration.setArchiveTimestampDigestAlgorithm(tsaRejectedTimestampDigest);
    configuration.setArchiveTimestampReferenceDigestAlgorithm(DigestAlgorithm.SHA256);

    TimestampBuilder timestampBuilder = TimestampBuilder.aTimestamp(container);

    assertTimestampDigestRejectedByConfiguredTsa(timestampBuilder);
  }

  @ParameterizedTest
  @EnumSource(value = DigestAlgorithm.class,
              names = {"SHA3_256", "SHA3_384", "SHA3_512"})
  void invokeTimestamping_WhenBuilderUsesSha3TimestampDigestFor1stTimestamp_ThrowsTsaRejection(
          DigestAlgorithm tsaRejectedTimestampDigest
  ) {
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);
    Container container = getDefaultContainerForTimestamping(configuration);

    TimestampBuilder timestampBuilder = TimestampBuilder.aTimestamp(container)
            .withTimestampDigestAlgorithm(tsaRejectedTimestampDigest)
            .withReferenceDigestAlgorithm(DigestAlgorithm.SHA256)
            .withTspSource(TestConstants.DEMO_TSA_RSA_URL);

    assertTimestampDigestRejectedByConfiguredTsa(timestampBuilder);
  }

  @ParameterizedTest
  @EnumSource(value = DigestAlgorithm.class,
              names = {"SHA3_256", "SHA3_384", "SHA3_512"})
  void invokeTimestamping_WhenBuilderUsesSha3TimestampDigestFor2ndTimestamp_ThrowsTsaRejection(
          DigestAlgorithm tsaRejectedTimestampDigest
  ) {
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);
    Container container = getDefaultContainerForTimestamping(configuration);
    container.addTimestamp(TimestampBuilder.aTimestamp(container).invokeTimestamping());

    TimestampBuilder timestampBuilder = TimestampBuilder.aTimestamp(container)
            .withTimestampDigestAlgorithm(tsaRejectedTimestampDigest)
            .withReferenceDigestAlgorithm(DigestAlgorithm.SHA256)
            .withTspSource(TestConstants.DEMO_TSA_RSA_URL);

    assertTimestampDigestRejectedByConfiguredTsa(timestampBuilder);
  }

  private static void assertTimestampDigestRejectedByConfiguredTsa(TimestampBuilder timestampBuilder) {
    DSSExternalResourceException caughtException = assertThrows(
            DSSExternalResourceException.class,
            timestampBuilder::invokeTimestamping
    );

    assertThat(caughtException.getMessage(),
               containsString("No timestamp token has been retrieved (TSP Status : request contains unknown algorithm / PKIFailureInfo: 0x80)"));
  }

  private static Stream<Arguments> supportedDigestAlgorithms() {
    List<DigestAlgorithm> supportedTimestampDigests = Arrays.asList(
            DigestAlgorithm.SHA256,
            DigestAlgorithm.SHA384,
            DigestAlgorithm.SHA512
    );

    List<DigestAlgorithm> supportedReferenceDigests = Arrays.asList(
            DigestAlgorithm.SHA256,
            DigestAlgorithm.SHA384,
            DigestAlgorithm.SHA512,
            DigestAlgorithm.SHA3_256,
            DigestAlgorithm.SHA3_384,
            DigestAlgorithm.SHA3_512
    );

    return supportedTimestampDigests.stream()
            .flatMap(timestampDigest -> supportedReferenceDigests.stream()
                    .map(referenceDigest -> Arguments.of(timestampDigest, referenceDigest)));
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
