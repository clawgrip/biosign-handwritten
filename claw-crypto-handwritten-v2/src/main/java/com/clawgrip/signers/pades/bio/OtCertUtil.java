package com.clawgrip.signers.pades.bio;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;

import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.oiw.OIWObjectIdentifiers;
import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.asn1.x509.BasicConstraints;
import org.spongycastle.asn1.x509.Extension;
import org.spongycastle.asn1.x509.KeyPurposeId;
import org.spongycastle.asn1.x509.KeyUsage;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.cert.X509ExtensionUtils;
import org.spongycastle.cert.X509v3CertificateBuilder;
import org.spongycastle.cert.jcajce.JcaX509CertificateConverter;
import org.spongycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.spongycastle.operator.DigestCalculator;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.operator.bc.BcDigestCalculatorProvider;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;

/** Utilidades de genraci&oacute;n de certificados.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
final class OtCertUtil {

	private static final int KEY_SIZE = 2048;
	private static final String PROVIDER = "SC"; //$NON-NLS-1$

	private OtCertUtil() {
		// No instanciable
	}

	/** Genera un certificado.
	 * @param subjectPrincipal Principal del titular del certificado.
	 * @param bioSign Paquete de firma biom&eacute;trica asociado al certificado.
	 * @param notBefore Fecha de inicio de validez del certificado.
	 * @return Entrada con el certificado y su conjunto de claves.
	 * @throws NoSuchAlgorithmException Cuando no se reconoce el algoritmo de generaci&oacute;n de claves.
	 * @throws CertificateException Cuando ocurre un error en la codificaci&oacute;n del certificado.
	 * @throws IOException Cuando ocurre un error al generar el certificado. */
	static PrivateKeyEntry generateCaCertificate(final String subjectPrincipal,
			                                     final byte[] bioSign,
			                                     final Date notBefore) throws CertificateException,
                                                                              IOException {
		// Generamos el par de claves...
		final KeyPairGenerator keyPairGenerator;
		try {
			keyPairGenerator = KeyPairGenerator.getInstance("RSA"); //$NON-NLS-1$
		}
		catch (final NoSuchAlgorithmException e1) {
			throw new CertificateException("Error generando el par de claves: " + e1, e1); //$NON-NLS-1$
		}
		keyPairGenerator.initialize(KEY_SIZE, new SecureRandom());
		final KeyPair keyPair = keyPairGenerator.generateKeyPair();

		//Creamos el generador de certificados
		final Date expirationDate = new Date();
		expirationDate.setTime(new Date().getTime()+(long)10*365*24*3600*1000);
		final X509v3CertificateBuilder generator = new JcaX509v3CertificateBuilder(
			new X500Name(subjectPrincipal),
			BigInteger.valueOf(new Random().nextInt()),
    		new Date(),
    		expirationDate,
    		new X500Name(subjectPrincipal),
    		keyPair.getPublic()
		);

		//Se incluyen los atributos del certificado CA
		final DigestCalculator digCalc;
		try {
			digCalc = new BcDigestCalculatorProvider().get(
				new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)
			);
		}
		catch (final OperatorCreationException e) {
			throw new IOException("No se ha podido inicializar el operador de cifrado: " + e, e); //$NON-NLS-1$
		}
        final X509ExtensionUtils x509ExtensionUtils = new X509ExtensionUtils(digCalc);

        final byte[] encoded = keyPair.getPublic().getEncoded();
        final SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(
    		ASN1Sequence.getInstance(encoded)
		);

		generator.addExtension(
			Extension.subjectKeyIdentifier,
			false,
			x509ExtensionUtils.createSubjectKeyIdentifier(subjectPublicKeyInfo)
		);
	    generator.addExtension(
    		Extension.basicConstraints,
    		true,
	        new BasicConstraints(true)
        );
	    generator.addExtension(
    		Extension.biometricInfo,
    		true,
	        new DEROctetString(bioSign)
        );

//	   PolicyInformation ::= SEQUENCE {
//	        policyIdentifier   CertPolicyId,
//	        policyQualifiers   SEQUENCE SIZE (1..MAX) OF
//	                                PolicyQualifierInfo OPTIONAL }
//
//	   CertPolicyId ::= OBJECT IDENTIFIER
//
//	   PolicyQualifierInfo ::= SEQUENCE {
//	        policyQualifierId  PolicyQualifierId,
//	        qualifier          ANY DEFINED BY policyQualifierId }
//
//	   -- policyQualifierIds for Internet policy qualifiers
//
//	   id-qt          OBJECT IDENTIFIER ::=  { id-pkix 2 }
//	   id-qt-cps      OBJECT IDENTIFIER ::=  { id-qt 1 }
//	   id-qt-unotice  OBJECT IDENTIFIER ::=  { id-qt 2 }
//
//	   PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps | id-qt-unotice )
//
//	   Qualifier ::= CHOICE {
//	        cPSuri           CPSuri,
//	        userNotice       UserNotice }
//
//	   CPSuri ::= IA5String
//
//	   UserNotice ::= SEQUENCE {
//	        noticeRef        NoticeReference OPTIONAL,
//	        explicitText     DisplayText OPTIONAL }
//
//	   NoticeReference ::= SEQUENCE {
//	        organization     DisplayText,
//	        noticeNumbers    SEQUENCE OF INTEGER }
//
//	   DisplayText ::= CHOICE {
//	        ia5String        IA5String      (SIZE (1..200)),
//	        visibleString    VisibleString  (SIZE (1..200)),
//	        bmpString        BMPString      (SIZE (1..200)),
//	        utf8String       UTF8String     (SIZE (1..200)) }


//	    boolean isCritical = true;
//	    PolicyQualifierInfo pqInfo = new PolicyQualifierInfo("aaa.bbb"); // the value you want
//	    PolicyInformation policyInfo = new PolicyInformation(PolicyQualifierId.id_qt_cps, new DERSequence(pqInfo));
//	    CertificatePolicies policies = new CertificatePolicies(policyInfo);
//	    certGen.addExtension(Extension.certificatePolicies, isCritical, policies);


	    final KeyUsage usage = new KeyUsage(
    		KeyUsage.nonRepudiation
		);
	    generator.addExtension(Extension.keyUsage, false, usage);

	    final ASN1EncodableVector purposes = new ASN1EncodableVector();
	    purposes.add(KeyPurposeId.anyExtendedKeyUsage);
	    generator.addExtension(
    		Extension.extendedKeyUsage,
    		false,
	        new DERSequence(purposes)
        );

	    //Firma con su propia clave privada (autofirmado)
	    final X509Certificate cert;
		try {
			cert = new JcaX509CertificateConverter().setProvider(PROVIDER).getCertificate(
				generator.build(
					new JcaContentSignerBuilder(PdfBioSigner.DEFAULT_SIGNATURE_ALGORITHM).setProvider(PROVIDER).build(
						keyPair.getPrivate()
					)
				)
			);
		}
		catch (final OperatorCreationException e) {
			throw new CertificateException("Error durante la construccion del certificado: " + e, e); //$NON-NLS-1$
		}

        //Definicion de propiedades del certificado
        return new PrivateKeyEntry(
    		keyPair.getPrivate(),
			new Certificate[] {
				cert
			}
		);
	}

}
