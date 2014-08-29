package eu.europa.ec.markt.dss.signature.asic;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSUnsupportedOperationException;
import eu.europa.ec.markt.dss.parameter.ASiCParameters;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.*;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.SignatureForm;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.asic.ASiCCMSDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.asic.ASiCXMLDocumentValidator;
import org.digidoc4j.Manifest;
import org.digidoc4j.api.DataFile;
import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.transform.TransformerException;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static eu.europa.ec.markt.dss.DSSXMLUtils.buildDOM;
import static java.util.Arrays.asList;
import static javax.xml.transform.TransformerFactory.newInstance;

/**
 * DigiDoc4JASiCSService is extension of ASiCSService class
 */
public class BDOCService extends ASiCSService {
  private static final String ZIP_ENTRY_DETACHED_FILE = "detached-file";
  private static final String ZIP_ENTRY_MIME_TYPE = "mimetype";
  private static final String ZIP_ENTRY_METAINF_XADES_SIGNATURE = "META-INF/signatures.xml";
  private static final String ASICS_EXTENSION = ".bdoc";
  private static final String ASICS_NS = "asic:XAdESSignatures";
  private static final String ASICS_URI = "http://uri.etsi.org/02918/v1.2.1#";
  private static final String ASIC_E_MIME_TYPE = "application/vnd.etsi.asic-e+zip";

  /**
   * This is the constructor to create an instance of the {@code BDocService}. A certificate verifier must be provided.
   *
   * @param certificateVerifier {@code CertificateVerifier} provides information on the sources to be used in the
   *                            validation process in the context of a signature.
   */
  public BDOCService(CertificateVerifier certificateVerifier) {
    super(certificateVerifier);
  }

  final Logger logger = LoggerFactory.getLogger(BDOCService.class);

  /**
   * ETSI TS 102 918 v1.2.1 (2012-02) <br />
   * <p>
   * Contents of Container ( 6.2.2 )
   * </p>
   * <ul>
   * <li>The file extension ".bdoc" should be used .</li>
   * <li>The root element of each signature content shall be either &lt;asic:XadESSignatures&gt; as specified in clause
   * A.5. Its the recommended format</li>
   * <li>The comment field in the ZIP header may be used to identify the type of the data object within the container.
   * <br />
   * If this field is present, it should be set with "mimetype=" followed by the mime type of the data object held in
   * the signed data object</li>
   * <li>The mimetype file can be used to support operating systems that rely on some content in specific positions in
   * a file.<br />
   * <ul>
   * <li>It has to be the first entry in the archive.</li>
   * <li>It cannot contain "Extra fields".</li>
   * <li>It cannot be compressed or encrypted inside the ZIP file</li>
   * </ul>
   * </li>
   * </ul>
   *
   * @param toSignDocument document where to add signature
   * @param parameters     signature parameters
   * @param signatureValue signature value
   * @return returns signed document
   * @throws DSSException when signing fails
   */
  @Override
  public DSSDocument signDocument(final DSSDocument toSignDocument, final SignatureParameters parameters,
                                  final byte[] signatureValue) throws DSSException {

    assertSigningDateInCertificateValidityRange(parameters);

    // Signs the toSignDocument first
    final SignatureParameters specificParameters = getParameters(parameters);
    // toSignDocument can be a simple file or an ASiC-S container
    DSSDocument contextToSignDocument = toSignDocument;
    SignedDocumentValidator validator = null;
    try {
      validator = SignedDocumentValidator.fromDocument(toSignDocument);
    } catch (Exception e) {
      logger.info(e.getMessage());
    }
    specificParameters.setDetachedContent(contextToSignDocument);
    if (validator != null && (validator instanceof ASiCCMSDocumentValidator
        || validator instanceof ASiCXMLDocumentValidator)) {

      contextToSignDocument = validator.getDetachedContent();
      specificParameters.setDetachedContent(contextToSignDocument);
      final DSSDocument contextSignature = validator.getDocument();
      parameters.aSiC().setEnclosedSignature(contextSignature);

      if (validator instanceof ASiCCMSDocumentValidator) {
        contextToSignDocument = contextSignature;
      }
    }

    final ASiCParameters asicParameters = specificParameters.aSiC();

    final DocumentSignatureService underlyingService = getSpecificService(specificParameters);

    final DSSDocument enclosedSignature = asicParameters.getEnclosedSignature();

    final SignatureForm asicSignatureForm = asicParameters.getAsicSignatureForm();
    final DSSDocument signature;

    if (SignatureForm.XAdES.equals(asicSignatureForm)) {
      signature = underlyingService.signDocument(contextToSignDocument, specificParameters, signatureValue);
    } else {
      throw new DSSUnsupportedOperationException(asicSignatureForm.name()
          + ": This form of the signature is not supported.");
    }

    final DSSDocument originalDocument = specificParameters.getDetachedContent();

    final ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
    final ZipOutputStream outZip = new ZipOutputStream(outBytes);

    final String toSignDocumentName = originalDocument.getName();


    if (asicParameters.isZipComment() && DSSUtils.isNotEmpty(toSignDocumentName)) {
      outZip.setComment("mimetype=" + ASIC_E_MIME_TYPE);
    }

    storeMimeType(asicParameters, outZip, ASIC_E_MIME_TYPE);
    storeSignedFile(originalDocument, outZip);
    buildXAdES(enclosedSignature, signature, outZip);
    storeManifest(asList(new DataFile(new byte[]{}, originalDocument.getName(),
        originalDocument.getMimeType().getCode())), outZip);

    DSSUtils.close(outZip);

    final byte[] documentBytes = outBytes.toByteArray();
    final String name = toSignDocumentName != null ? toSignDocumentName + ASICS_EXTENSION : null;
    final InMemoryDocument asicSignature = new InMemoryDocument(documentBytes, name, MimeType.ASICS);
    parameters.setDeterministicId(null);
    return asicSignature;
  }

  private void storeManifest(List<DataFile> dataFiles, ZipOutputStream outZip) {
    Manifest manifest = new Manifest();
    manifest.addFileEntry(dataFiles);
    try {
      outZip.putNextEntry(new ZipEntry("META-INF/manifest.xml"));
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      manifest.save(out);
      outZip.write(out.toByteArray());
    } catch (IOException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e);
    }
  }

  /**
   * Creates a specific XAdES/CAdES signature parameters on the base of the provided parameters.
   * Forces the signature packaging to
   * DETACHED
   *
   * @param parameters must provide signingToken, PrivateKeyEntry and date
   * @return new specific instance for XAdES
   */
  private SignatureParameters getParameters(final SignatureParameters parameters) {

    final SignatureParameters specificParameters = new SignatureParameters(parameters);
    final SignatureLevel asicProfile = parameters.getSignatureLevel();
    SignatureLevel specificLevel;
    switch (asicProfile) {
      case ASiC_E_BASELINE_B:
        specificLevel = SignatureLevel.XAdES_BASELINE_B;
        break;
      case ASiC_E_BASELINE_T:
        specificLevel = SignatureLevel.XAdES_BASELINE_T;
        break;
      case ASiC_E_BASELINE_LT:
        specificLevel = SignatureLevel.XAdES_BASELINE_LT;
        break;
      default:
        throw new DSSException("Unsupported format: " + asicProfile.name());
    }
    specificParameters.setSignatureLevel(specificLevel);
    specificParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
    return specificParameters;
  }


  /**
   * This method creates a XAdES signature. When adding a new signature,
   * this one is appended to the already present signatures.
   *
   * @param contextSignature already present signatures
   * @param signature        signature being created
   * @param outZip           destination {@code ZipOutputStream}
   * @throws DSSException
   */
  private void buildXAdES(final DSSDocument contextSignature, final DSSDocument signature,
                          final ZipOutputStream outZip) throws DSSException {

    try {

      final ZipEntry entrySignature = new ZipEntry(ZIP_ENTRY_METAINF_XADES_SIGNATURE);
      outZip.putNextEntry(entrySignature);
      // Creates the XAdES signature
      final Document xmlSignatureDoc = buildDOM(signature);
      final Element documentElement = xmlSignatureDoc.getDocumentElement();
      final Element xmlSignatureElement = (Element) xmlSignatureDoc.removeChild(documentElement);

      final Document xmlXAdESDoc;
      if (contextSignature != null) {

        final Document contextXmlSignatureDoc = buildDOM(contextSignature);
        final Element contextDocumentElement = contextXmlSignatureDoc.getDocumentElement();
        contextXmlSignatureDoc.adoptNode(xmlSignatureElement);
        contextDocumentElement.appendChild(xmlSignatureElement);
        xmlXAdESDoc = contextXmlSignatureDoc;
      } else {

        xmlXAdESDoc = DSSXMLUtils.createDocument(ASICS_URI, ASICS_NS, xmlSignatureElement);
      }
      newInstance().newTransformer().transform(new DOMSource(xmlXAdESDoc), new StreamResult(outZip));
    } catch (IOException e) {
      throw new DSSException(e);
    } catch (TransformerException e) {
      throw new DSSException(e);
    }
  }

  /**
   * Creates asic-s container with given signature
   *
   * @param toSignDocument document where to add signature
   * @param signature      xades signature
   * @return asic-s container with signature
   * @throws DSSException when xml transformation fails or writing to zip stream fails
   */
  public DSSDocument createContainer(final DSSDocument toSignDocument, DSSDocument signature) throws DSSException {
    final ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
    final ZipOutputStream outZip = new ZipOutputStream(outBytes);

    final String toSignDocumentName = toSignDocument.getName();

    outZip.setComment("mimetype=" + ASIC_E_MIME_TYPE);

    ASiCParameters asicParameters = new ASiCParameters();
    asicParameters.setMimeType(ASIC_E_MIME_TYPE);

    storeMimeType(asicParameters, outZip, ASIC_E_MIME_TYPE);
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

    storeManifest(asList(new DataFile(new byte[]{}, toSignDocument.getName(),
        toSignDocument.getMimeType().getCode())), outZip);

    DSSUtils.close(outZip);

    final byte[] documentBytes = outBytes.toByteArray();
    final String name = toSignDocumentName != null ? toSignDocumentName + ASICS_EXTENSION : null;
    return new InMemoryDocument(documentBytes, name, MimeType.ASICS);
  }

  private void storeMimeType(final ASiCParameters asicParameters, final ZipOutputStream outZip,
                             final String containedFileMimeType) throws DSSException {

    final byte[] mimeTypeBytes = getMimeTypeBytes(asicParameters, containedFileMimeType);
    final ZipEntry entryMimeType = getZipEntryMimeType(mimeTypeBytes);

    writeZipEntry(outZip, mimeTypeBytes, entryMimeType);
  }

  private void writeZipEntry(final ZipOutputStream outZip, final byte[] mimeTypeBytes,
                             final ZipEntry entryMimeType) throws DSSException {

    try {
      outZip.putNextEntry(entryMimeType);
      outZip.write(mimeTypeBytes);
    } catch (IOException e) {
      throw new DSSException(e);
    }
  }

  private void storeSignedFile(final DSSDocument toSignDocument, final ZipOutputStream outZip) throws DSSException {

    String toSignDocumentName = toSignDocument.getName();
    ZipEntry entryDocument = new ZipEntry(toSignDocumentName != null ? toSignDocumentName : ZIP_ENTRY_DETACHED_FILE);
    outZip.setLevel(ZipEntry.DEFLATED);

    try {
      outZip.putNextEntry(entryDocument);
      DSSUtils.copy(toSignDocument.openStream(), outZip);
    } catch (IOException e) {
      throw new DSSException(e);
    }
  }

  private byte[] getMimeTypeBytes(final ASiCParameters asicParameters, final String containedFileMimeType) {

    final byte[] mimeTypeBytes;
    final String asicParameterMimeType = asicParameters.getMimeType();
    if (DSSUtils.isBlank(asicParameterMimeType)) {
      mimeTypeBytes = containedFileMimeType.getBytes();
    } else {
      mimeTypeBytes = asicParameterMimeType.getBytes();
    }
    return mimeTypeBytes;
  }

  private ZipEntry getZipEntryMimeType(final byte[] mimeTypeBytes) {
    final ZipEntry entryMimeType = new ZipEntry(ZIP_ENTRY_MIME_TYPE);
    entryMimeType.setMethod(ZipEntry.STORED);
    entryMimeType.setSize(mimeTypeBytes.length);
    entryMimeType.setCompressedSize(mimeTypeBytes.length);

    final CRC32 crc = new CRC32();
    crc.update(mimeTypeBytes);
    entryMimeType.setCrc(crc.getValue());

    return entryMimeType;
  }
}
