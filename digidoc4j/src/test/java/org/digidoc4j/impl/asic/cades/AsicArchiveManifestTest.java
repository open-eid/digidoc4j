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

import eu.europa.esig.dss.asic.cades.signature.manifest.ASiCEWithCAdESArchiveManifestBuilder;
import eu.europa.esig.dss.asic.cades.signature.manifest.ASiCWithCAdESSignatureManifestBuilder;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.digidoc4j.exceptions.TechnicalException;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Set;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

public class AsicArchiveManifestTest {

  private static final String TEST_FILE_CONTENT = "This is a test file.";
  private static final String TEST_FILE_NAME = "test.txt";
  private static final MimeType TEST_FILE_MIMETYPE = MimeTypeEnum.TEXT;

  @Test
  public void createInstance_WhenWrappedDocumentIsMock_DocumentIsWrappedWithoutParsingIt() {
    DSSDocument manifestDocument = mock(DSSDocument.class);
    AsicArchiveManifest asicArchiveManifest = new AsicArchiveManifest(manifestDocument);

    DSSDocument result = asicArchiveManifest.getManifestDocument();

    assertThat(result, sameInstance(manifestDocument));
    verifyNoInteractions(manifestDocument);
  }

  @Test
  public void getNonNullEntryNames_WhenDocumentIsNotParsable_ThrowsException() {
    DSSDocument manifestDocument = new InMemoryDocument(
            "Not XML".getBytes(StandardCharsets.UTF_8),
            "ManifestName.xml",
            MimeTypeEnum.XML
    );
    AsicArchiveManifest asicArchiveManifest = new AsicArchiveManifest(manifestDocument);

    TechnicalException caughtException = assertThrows(
            TechnicalException.class,
            asicArchiveManifest::getNonNullEntryNames
    );

    assertThat(caughtException.getMessage(), equalTo("Failed to parse manifest file: ManifestName.xml"));
  }

  @Test
  public void getNonNullEntryNames_WhenDocumentIsNotArchiveManifest_ThrowsException() {
    DSSDocument manifestDocument = new ASiCWithCAdESSignatureManifestBuilder(
            createAsicContentWithTestFile(ASiCContainerType.ASiC_E),
            DigestAlgorithm.SHA256,
            "signature"
    ).build();
    AsicArchiveManifest asicArchiveManifest = new AsicArchiveManifest(manifestDocument);

    TechnicalException caughtException = assertThrows(
            TechnicalException.class,
            asicArchiveManifest::getNonNullEntryNames
    );

    assertThat(
            caughtException.getMessage(),
            equalTo("Not an ASiCArchiveManifest: META-INF/ASiCManifest001.xml")
    );
  }

  @Test
  public void getNonNullEntryNames_WhenDocumentIsArchiveManifest_Returns() {
    DSSDocument manifestDocument = new ASiCEWithCAdESArchiveManifestBuilder(
            createAsicContentWithTestFile(ASiCContainerType.ASiC_S),
            null,
            DigestAlgorithm.SHA512,
            "timestamp"
    ).build();
    AsicArchiveManifest asicArchiveManifest = new AsicArchiveManifest(manifestDocument);

    Set<String> result = asicArchiveManifest.getNonNullEntryNames();

    assertThat(result, hasSize(1));
    assertThat(result, contains(TEST_FILE_NAME));
  }

  private static ASiCContent createAsicContentWithTestFile(ASiCContainerType containerType) {
    ASiCContent asicContent = new ASiCContent();
    asicContent.setContainerType(containerType);
    asicContent.getSignedDocuments().add(new InMemoryDocument(
            TEST_FILE_CONTENT.getBytes(StandardCharsets.UTF_8),
            TEST_FILE_NAME,
            TEST_FILE_MIMETYPE
    ));
    return asicContent;
  }

}
