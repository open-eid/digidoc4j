package org.digidoc4j.impl.asic.tsl;

import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.Token;
import eu.europa.esig.dss.spi.x509.CertificatePool;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.cms.SignerId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;
import java.security.PublicKey;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * A certificate pool that includes certificates from trusted certificate source's pool without needing to copy them,
 * and also allows to pool new certificates without polluting the trusted certificate source's pool.
 *
 * When using lazily loadable TSL as the trusted source then TSL initialization is not triggered until the actual pool's
 * content is being interacted with. This allows postponing the loading of TSL until it is really needed.
 */
public class CompoundCertificatePool extends CertificatePool {

    private static final Logger logger = LoggerFactory.getLogger(CompoundCertificatePool.class);

    private final CertificateSource trustedCertificateSource;

    public CompoundCertificatePool(CertificateSource trustedCertificateSource) {
        this.trustedCertificateSource = Objects.requireNonNull(trustedCertificateSource, "Trusted certificate source must be provided");
    }

    @Override
    public CertificateToken getInstance(final CertificateToken certificateToAdd, final CertificateSourceType certSource) {
        if (getTrustedCertificatePool().getSources(certificateToAdd).contains(certSource)) {
            return certificateToAdd;
        } else {
            return super.getInstance(certificateToAdd, certSource);
        }
    }

    @Override
    public boolean isTrusted(CertificateToken cert) {
        return getTrustedCertificatePool().isTrusted(cert) || super.isTrusted(cert);
    }

    @Override
    public Set<CertificateSourceType> getSources(CertificateToken certificateToken) {
        return mergeToSet(getTrustedCertificatePool().getSources(certificateToken), super.getSources(certificateToken));
    }

    @Override
    public List<CertificateToken> getIssuers(final Token token) {
        return mergeLists(getTrustedCertificatePool().getIssuers(token), super.getIssuers(token));
    }

    /**
     * Reimplemented {@link CertificatePool#getIssuer(Token)} to find the best match from among all the entries!
     */
    @Override
    public CertificateToken getIssuer(final Token token) {
        final List<CertificateToken> issuers = getIssuers(token);
        if (Utils.isCollectionNotEmpty(issuers)) {
            return issuers.stream()
                    .filter(i -> i.isValidOn(token.getCreationDate()))
                    .findFirst()
                    .orElseGet(() -> {
                        logger.warn("No issuer found for the token creation date. The process continues with an issuer which has the same public key.");
                        return issuers.stream().findFirst().get();
                    });
        } else {
            return null;
        }
    }

    @Override
    public CertificateToken getTrustAnchor(CertificateToken cert) {
        CertificateToken trustAnchor = getTrustedCertificatePool().getTrustAnchor(cert);
        if (trustAnchor != null) return trustAnchor;

        trustAnchor = super.getTrustAnchor(cert);
        if (trustAnchor != null) return trustAnchor;

        return super.getIssuers(cert).stream()
                .map(this::findTrustAnchorRecursively)
                .filter(Objects::nonNull)
                .findFirst()
                .orElse(null);
    }

    private CertificateToken findTrustAnchorRecursively(CertificateToken cert) {
        CertificateToken trustAnchor = getTrustedCertificatePool().getTrustAnchor(cert);
        if (trustAnchor != null) return trustAnchor;

        return super.getIssuers(cert).stream()
                .map(this::findTrustAnchorRecursively)
                .filter(Objects::nonNull)
                .findFirst()
                .orElse(null);
    }

    @Override
    public Set<CertificateToken> get(X500Principal x500Principal) {
        return mergeToSet(getTrustedCertificatePool().get(x500Principal), super.get(x500Principal));
    }

    @Override
    public List<CertificateToken> get(PublicKey publicKey) {
        return mergeLists(getTrustedCertificatePool().get(publicKey), super.get(publicKey));
    }

    @Override
    public List<CertificateToken> getBySki(final byte[] expectedSki) {
        return mergeLists(getTrustedCertificatePool().getBySki(expectedSki), super.getBySki(expectedSki));
    }

    @Override
    public List<CertificateToken> getBySignerId(SignerId signerId) {
        return mergeLists(getTrustedCertificatePool().getBySignerId(signerId), super.getBySignerId(signerId));
    }

    @Override
    public void importCerts(final CertificateSource certificateSource) {
        final List<CertificateToken> certificatesList = certificateSource.getCertificates();
        final CertificateSourceType source = certificateSource.getCertificateSourceType();
        certificatesList.forEach(c -> {
            final Set<CertificateSourceType> certSources = getTrustedCertificatePool().getSources(c);
            if (!certSources.contains(source)) super.getInstance(c, source);
        });
    }

    @Override
    public int getNumberOfEntities() {
        return getTrustedCertificatePool().getNumberOfEntities() + super.getNumberOfEntities();
    }

    @Override
    public int getNumberOfCertificates() {
        return mergeToSet(getTrustedCertificatePool().getCertificateTokens(), super.getCertificateTokens()).size();
    }

    @Override
    public List<CertificateToken> getCertificateTokens() {
        return mergeLists(getTrustedCertificatePool().getCertificateTokens(), super.getCertificateTokens());
    }

    private CertificatePool getTrustedCertificatePool() {
        logger.debug("Accessing trusted certificate pool");
        return trustedCertificateSource.getCertificatePool();
    }

    private static <T> Set<T> mergeToSet(Collection<T> primaryCollection, Collection<T> secondaryCollection) {
        HashSet<T> mergedSet = new HashSet<>(primaryCollection);
        mergedSet.addAll(secondaryCollection);
        return mergedSet;
    }

    private static <T> List<T> mergeLists(List<T> primaryList, List<T> secondaryList) {
        LinkedHashSet<T> mergedSet = new LinkedHashSet<>(primaryList);
        mergedSet.addAll(secondaryList);
        return mergedSet.stream().collect(Collectors.toList());
    }

}
