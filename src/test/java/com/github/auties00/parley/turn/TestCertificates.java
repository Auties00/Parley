package com.github.auties00.parley.turn;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

/// A self-signed ECDSA P-256 certificate for `localhost` and `127.0.0.1`, built with BouncyCastle's ASN.1 classes,
/// and the TLS contexts of a server presenting it and a client trusting it.
public final class TestCertificates {
    /// The shared instance, generated once per test run.
    private static final TestCertificates INSTANCE = new TestCertificates();

    /// The server context.
    private final SSLContext serverContext;

    /// The client context, which trusts only the test certificate.
    private final SSLContext clientContext;

    /// Generates the key pair and certificate and builds the contexts.
    private TestCertificates() {
        try {
            var generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            var keyPair = generator.generateKeyPair();
            var now = System.currentTimeMillis();
            var name = new X500Name("CN=localhost");
            var algorithm = new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256);
            var tbs = new V3TBSCertificateGenerator();
            tbs.setSerialNumber(new ASN1Integer(BigInteger.valueOf(now)));
            tbs.setIssuer(name);
            tbs.setSubject(name);
            tbs.setStartDate(new Time(new Date(now - 3_600_000L)));
            tbs.setEndDate(new Time(new Date(now + 86_400_000L)));
            tbs.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));
            tbs.setSignature(algorithm);
            var extensions = new ExtensionsGenerator();
            extensions.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName[]{
                    new GeneralName(GeneralName.dNSName, "localhost"),
                    new GeneralName(GeneralName.iPAddress, "127.0.0.1")}));
            tbs.setExtensions(extensions.generate());
            var certificateBody = tbs.generateTBSCertificate();
            var signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(keyPair.getPrivate());
            signer.update(certificateBody.getEncoded(ASN1Encoding.DER));
            var vector = new ASN1EncodableVector();
            vector.add(certificateBody);
            vector.add(algorithm);
            vector.add(new DERBitString(signer.sign()));
            var certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(new DERSequence(vector).getEncoded()));
            var password = "parley".toCharArray();
            var keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            keyStore.setKeyEntry("server", keyPair.getPrivate(), password, new java.security.cert.Certificate[]{certificate});
            var keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagers.init(keyStore, password);
            serverContext = SSLContext.getInstance("TLS");
            serverContext.init(keyManagers.getKeyManagers(), null, null);
            var trustStore = KeyStore.getInstance("PKCS12");
            trustStore.load(null, null);
            trustStore.setCertificateEntry("server", certificate);
            var trustManagers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagers.init(trustStore);
            clientContext = SSLContext.getInstance("TLS");
            clientContext.init(null, trustManagers.getTrustManagers(), null);
        } catch (Exception exception) {
            throw new IllegalStateException("cannot build the test certificate", exception);
        }
    }

    /// {@return the TLS context of a server presenting the certificate}
    public static SSLContext serverContext() {
        return INSTANCE.serverContext;
    }

    /// {@return the TLS context of a client that trusts only the certificate}
    public static SSLContext clientContext() {
        return INSTANCE.clientContext;
    }
}
