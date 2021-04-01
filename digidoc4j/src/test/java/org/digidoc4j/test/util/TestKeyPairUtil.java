package org.digidoc4j.test.util;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;

public final class TestKeyPairUtil {

    private static final String EC_KEY_ALGORITHM = "ECDSA";

    public static AsymmetricCipherKeyPair generateEcKeyPair(ECDomainParameters ecDomainParameters) {
        ECKeyGenerationParameters ecKeyGenerationParameters = new ECKeyGenerationParameters(ecDomainParameters, new SecureRandom());
        ECKeyPairGenerator ecKeyPairGenerator = new ECKeyPairGenerator();
        ecKeyPairGenerator.init(ecKeyGenerationParameters);
        return ecKeyPairGenerator.generateKeyPair();
    }

    public static AsymmetricCipherKeyPair generateEcKeyPair(String ecCurveName) {
        ECNamedCurveParameterSpec ecNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec(ecCurveName);
        Objects.requireNonNull(ecNamedCurveParameterSpec, "No such EC curve found: " + ecCurveName);
        ECDomainParameters ecDomainParameters = ECUtil.getDomainParameters(null, ecNamedCurveParameterSpec);
        return generateEcKeyPair(ecDomainParameters);
    }

    public static PrivateKey toPrivateKey(ECPrivateKeyParameters ecPrivateKeyParameters) {
        try {
            ECParameterSpec ecParameterSpec = toECParameterSpec(ecPrivateKeyParameters.getParameters());
            ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(ecPrivateKeyParameters.getD(), ecParameterSpec);
            return createKeyFactoryForEC().generatePrivate(ecPrivateKeySpec);
        } catch (InvalidKeySpecException e) {
            throw new IllegalStateException("Failed to convert to private key", e);
        }
    }

    public static PublicKey toPublicKey(ECPublicKeyParameters ecPublicKeyParameters) {
        try {
            ECParameterSpec ecParameterSpec = toECParameterSpec(ecPublicKeyParameters.getParameters());
            ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(ecPublicKeyParameters.getQ(), ecParameterSpec);
            return createKeyFactoryForEC().generatePublic(ecPublicKeySpec);
        } catch (InvalidKeySpecException e) {
            throw new IllegalStateException("Failed to convert to private key", e);
        }
    }

    private static KeyFactory createKeyFactoryForEC() {
        try {
            return KeyFactory.getInstance(EC_KEY_ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Unsupported key algorithm: " + EC_KEY_ALGORITHM, e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("Unsupported provider: " + BouncyCastleProvider.PROVIDER_NAME, e);
        }
    }

    private static ECParameterSpec toECParameterSpec(ECDomainParameters ecDomainParameters) {
        ECCurve curve = ecDomainParameters.getCurve();
        ECPoint g = ecDomainParameters.getG();
        BigInteger n = ecDomainParameters.getN();
        BigInteger h = ecDomainParameters.getH();
        byte[] seed = ecDomainParameters.getSeed();

        if (ecDomainParameters instanceof ECNamedDomainParameters) {
            ECNamedDomainParameters ecNamedDomainParameters = (ECNamedDomainParameters) ecDomainParameters;
            String name = ECUtil.getCurveName(ecNamedDomainParameters.getName());
            return new ECNamedCurveParameterSpec(name, curve, g, n, h, seed);
        } else {
            return new ECParameterSpec(curve, g, n, h, seed);
        }
    }

    private TestKeyPairUtil() {}

}
