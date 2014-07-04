package org.digidoc4j;

import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.asic.ASiCEService;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;

import static org.digidoc4j.ContainerInterface.DocumentType.ASIC_E;

/**
 * Offers functionality for handling data files and signatures in a container.
 * <p>
 * A container can contain several files and all those files can be signed using signing certificates.
 * A container can only be signed if it contains data files.
 * </p><p>
 * Data files can be added and removed from a container only if the container is not signed.
 * To modify the data list of a signed container by adding or removing datafiles you must first
 * remove all the signatures.
 * </p>
 */
public class BDocContainer extends ASiCSContainer {

    private CommonCertificateVerifier commonCertificateVerifier;
    private SignatureParameters signatureParameters;

    /**
     * Create a new container object of ASIC type Container.
     */
    public BDocContainer() {
        signatureParameters = new SignatureParameters();
        signatureParameters.setSignatureLevel(SignatureLevel.ASiC_E_BASELINE_B);
        signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
        signatureParameters.setDigestAlgorithm(eu.europa.ec.markt.dss.DigestAlgorithm.SHA256);
        commonCertificateVerifier = new CommonCertificateVerifier();

        asicService = new ASiCEService(commonCertificateVerifier);
    }


    /**
     * Opens the container from a file.
     *
     * @param path container file name with path
     */
    public BDocContainer(String path) {
        super(path);
    }

    @Override
    public DocumentType getDocumentType() {
        return ASIC_E;
    }
}






