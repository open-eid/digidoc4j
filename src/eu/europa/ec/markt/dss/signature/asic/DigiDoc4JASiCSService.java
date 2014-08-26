package eu.europa.ec.markt.dss.signature.asic;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.parameter.ASiCParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.MimeType;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;

import javax.xml.transform.TransformerException;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static eu.europa.ec.markt.dss.DSSXMLUtils.buildDOM;
import static javax.xml.transform.TransformerFactory.newInstance;

public class DigiDoc4JASiCSService extends ASiCSService {
  private static final String ZIP_ENTRY_DETACHED_FILE = "detached-file";
  private static final String ZIP_ENTRY_MIMETYPE = "mimetype";
  private static final String ZIP_ENTRY_METAINF_XADES_SIGNATURE = "META-INF/signatures.xml";
  private static final String ASICS_EXTENSION = ".asics";

  /**
   * This is the constructor to create an instance of the {@code ASiCSService}. A certificate verifier must be provided.
   *
   * @param certificateVerifier {@code CertificateVerifier} provides information on the sources to be used in the validation process in the context of a signature.
   */
  public DigiDoc4JASiCSService(CertificateVerifier certificateVerifier) {
    super(certificateVerifier);
  }

  public DSSDocument createContainer(final DSSDocument toSignDocument, DSSDocument signature) throws DSSException {
    final ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
    final ZipOutputStream outZip = new ZipOutputStream(outBytes);

    final String toSignDocumentName = toSignDocument.getName();

    final MimeType signedFileMimeType = toSignDocument.getMimeType();
    outZip.setComment("mimetype=" + signedFileMimeType.getCode());

    ASiCParameters asicParameters = new ASiCParameters();
    asicParameters.setMimeType(signedFileMimeType.getCode());

    storeMimetype(asicParameters, outZip, signedFileMimeType);

    storeSignedFile(toSignDocument, outZip);
    try {
      final ZipEntry entrySignature = new ZipEntry(ZIP_ENTRY_METAINF_XADES_SIGNATURE);
      outZip.putNextEntry(entrySignature);
      newInstance().newTransformer().transform(new DOMSource(buildDOM(signature)), new StreamResult(outZip));

    } catch (TransformerException e) {
      throw new DSSException(e);
    } catch (IOException e) {
      throw new DSSException(e);
    }

    DSSUtils.close(outZip);

    final byte[] documentBytes = outBytes.toByteArray();
    final String name = toSignDocumentName != null ? toSignDocumentName + ASICS_EXTENSION : null;
    final InMemoryDocument asicSignature = new InMemoryDocument(documentBytes, name, MimeType.ASICS);
    return asicSignature;
  }


  private void storeMimetype(final ASiCParameters asicParameters, final ZipOutputStream outZip, final MimeType containedFileMimeType) throws DSSException {

    final byte[] mimeTypeBytes = getMimeTypeBytes(asicParameters, containedFileMimeType);
    final ZipEntry entryMimetype = getZipEntryMimeType(mimeTypeBytes);

    writeZipEntry(outZip, mimeTypeBytes, entryMimetype);
  }

  private void writeZipEntry(final ZipOutputStream outZip, final byte[] mimeTypeBytes, final ZipEntry entryMimetype) throws DSSException {

    try {
      outZip.putNextEntry(entryMimetype);
      outZip.write(mimeTypeBytes);
    } catch (IOException e) {
      throw new DSSException(e);
    }
  }

  private void storeSignedFile(final DSSDocument toSignDocument, final ZipOutputStream outZip) throws DSSException {

    final String toSignDocumentName = toSignDocument.getName();
    final ZipEntry entryDocument = new ZipEntry(toSignDocumentName != null ? toSignDocumentName : ZIP_ENTRY_DETACHED_FILE);
    outZip.setLevel(ZipEntry.DEFLATED);

    try {
      outZip.putNextEntry(entryDocument);
      DSSUtils.copy(toSignDocument.openStream(), outZip);
    } catch (IOException e) {
      throw new DSSException(e);
    }
  }

  private byte[] getMimeTypeBytes(final ASiCParameters asicParameters, final MimeType containedFileMimeType) {

    final byte[] mimeTypeBytes;
    final String asicParameterMimeType = asicParameters.getMimeType();
    if (DSSUtils.isBlank(asicParameterMimeType)) {
      mimeTypeBytes = containedFileMimeType.getCode().getBytes();
    } else {
      mimeTypeBytes = asicParameterMimeType.getBytes();
    }
    return mimeTypeBytes;
  }


  private ZipEntry getZipEntryMimeType(final byte[] mimeTypeBytes) {

    final ZipEntry entryMimetype = new ZipEntry(ZIP_ENTRY_MIMETYPE);
    entryMimetype.setMethod(ZipEntry.STORED);
    entryMimetype.setSize(mimeTypeBytes.length);
    entryMimetype.setCompressedSize(mimeTypeBytes.length);
    final CRC32 crc = new CRC32();
    crc.update(mimeTypeBytes);
    entryMimetype.setCrc(crc.getValue());
    return entryMimetype;
  }
}
