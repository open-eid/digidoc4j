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

import eu.europa.esig.dss.asic.common.validation.ASiCManifestParser;
import eu.europa.esig.dss.enumerations.ASiCManifestTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.ManifestEntry;
import eu.europa.esig.dss.model.ManifestFile;
import org.digidoc4j.exceptions.TechnicalException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.Collections;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * An entity for handling instances of {@code ASiCArchiveManifest}.
 */
public class AsicArchiveManifest implements Serializable {

  private static final Logger log = LoggerFactory.getLogger(AsicArchiveManifest.class);

  private final DSSDocument manifestDocument;

  private transient Set<String> uniqueNonNullEntryNames;

  /**
   * Creates an instance AsicArchiveManifest by wrapping the specified DSSDocument.
   * NB: the constructor does not parse the manifest! The manifest is parsed lazily as needed.
   *
   * @param manifestDocument DSSDocument of an ASiCArchiveManifest
   */
  public AsicArchiveManifest(DSSDocument manifestDocument) {
    this.manifestDocument = Objects.requireNonNull(manifestDocument);
  }

  /**
   * Returns the DSSDocument of the manifest.
   *
   * @return DSSDocument of the manifest
   */
  public DSSDocument getManifestDocument() {
    return manifestDocument;
  }

  /**
   * Returns the set of non-null names of this manifest's entries.
   * Calling this method triggers parsing process of the manifest if it has not been parsed already.
   *
   * @return set of non-null manifest entry names
   */
  public Set<String> getNonNullEntryNames() {
    if (uniqueNonNullEntryNames == null) {
      parseManifestContent();
    }

    return uniqueNonNullEntryNames;
  }

  private void parseManifestContent() {
    log.debug("Parsing ASiCArchiveManifest from manifest document: {}", manifestDocument);
    ManifestFile manifestFile = ASiCManifestParser.getManifestFile(manifestDocument);
    if (manifestFile == null) {
      throw new TechnicalException("Failed to parse manifest file: " + manifestDocument.getName());
    } else if (manifestFile.getManifestType() != ASiCManifestTypeEnum.ARCHIVE_MANIFEST) {
      throw new TechnicalException("Not an ASiCArchiveManifest: " + manifestDocument.getName());
    }

    uniqueNonNullEntryNames = Collections.unmodifiableSet(
            manifestFile.getEntries().stream()
                    .map(ManifestEntry::getFileName)
                    .filter(Objects::nonNull)
                    .collect(Collectors.toSet())
    );
  }

}
