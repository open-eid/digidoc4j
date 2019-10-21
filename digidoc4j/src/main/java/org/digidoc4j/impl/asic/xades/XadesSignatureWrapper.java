/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.xades;

import eu.europa.esig.dss.model.DSSDocument;

import java.io.Serializable;

public class XadesSignatureWrapper implements Serializable {

    private final XadesSignature signature;
    private final DSSDocument signatureDocument;

    public XadesSignatureWrapper(XadesSignature signature, DSSDocument signatureDocument) {
        this.signature = signature;
        this.signatureDocument = signatureDocument;
    }

    public XadesSignature getSignature() {
        return signature;
    }

    public DSSDocument getSignatureDocument() {
        return signatureDocument;
    }
}
