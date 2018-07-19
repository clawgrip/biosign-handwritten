package com.clawgrip.signers.pades.bio;

import java.io.IOException;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.GregorianCalendar;
import java.util.Properties;

import org.spongycastle.jce.provider.BouncyCastleProvider;

import es.gob.afirma.core.AOException;
import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.core.signers.AOPkcs1Signer;
import es.gob.afirma.core.signers.AOSignConstants;
import es.gob.afirma.core.signers.AdESPolicy;
import es.gob.afirma.signers.cades.CAdESSignerMetadataHelper;
import es.gob.afirma.signers.cades.CAdESTriPhaseSigner;
import es.gob.afirma.signers.cades.CommitmentTypeIndicationsHelper;
import es.gob.afirma.signers.pades.InvalidPdfException;
import es.gob.afirma.signers.pades.PAdESTriPhaseSigner;
import es.gob.afirma.signers.pades.PdfExtraParams;
import es.gob.afirma.signers.pades.PdfSessionManager;
import es.gob.afirma.signers.pades.PdfSignResult;
import es.gob.afirma.signers.pades.PdfTriPhaseSession;

/** Firmador biom&eacute;trico de PDF.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class PdfBioSigner {

	private static final String PDF_OID = "1.2.826.0.1089.1.5"; //$NON-NLS-1$
	private static final String PDF_DESC = "Documento en formato PDF"; //$NON-NLS-1$

    /** Referencia a la &uacute;ltima p&aacute;gina del documento PDF. */
    public static final int LAST_PAGE = -1;

	// Anadimos SpongyCastle como proveedor
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	/** Algoritmo de firma por defecto. */
	public final static String DEFAULT_SIGNATURE_ALGORITHM = "SHA512withRSA"; //$NON-NLS-1$

	/** Algoritmo por defecto para huellas digitales. */
	public final static String DEFAULT_DIGEST_ALGORITHM = "SHA-512"; //$NON-NLS-1$

	private PdfBioSigner() {
		// No instanciable
	}

	/** Firma biom&eacute;tricamente un PDF.
	 * @param pdf PDF a firmar.
	 * @param xParams Par&aacute;metros adicionales.
	 * @param subjectPrincipal Nombre X.500 del firmante.
	 * @param bioSign Firma biom&eacute;trica (ISO 19794-7).
	 * @param trustedPartyCert Certificado del tercero de confianza para cifrado.
	 * @return PDF firmado.
	 * @throws AOException En cualquier otro error.
	 * @throws IOException Si hay problemas en la lectura o escritura de datos.
	 * @throws InvalidPdfException Si el PDF est&aacute; corrupto o no es un PDF.
	 * @throws CertificateException Si hay problemas generando el certificado.
	 * @throws NoSuchAlgorithmException Si el entorno de ejecuci&oacute;n no soporta alg&uacute;n algoritmo necesario. */
	public static byte[] bioSignPdf(final byte[] pdf,
			                       final Properties xParams,
			                       final String subjectPrincipal,
			                       final byte[] bioSign,
			                       final X509Certificate trustedPartyCert) throws InvalidPdfException,
	                                                                              IOException,
	                                                                              AOException,
	                                                                              CertificateException,
	                                                                              NoSuchAlgorithmException {
		final GregorianCalendar signTime = new GregorianCalendar();

        final Properties extraParams = xParams != null ? xParams : new Properties();

		extraParams.put(PdfExtraParams.DO_NOT_USE_CERTCHAIN_ON_POSTSIGN, Boolean.TRUE.toString());

        final PdfTriPhaseSession ptps = PdfSessionManager.getSessionData(
    		pdf,
    		null, // signerCertificateChain
    		signTime,
    		extraParams // extraParams
		);

	    // La norma PAdES establece que si el algoritmo de huella digital es SHA1 debe usarse SigningCertificate, y en cualquier
	    // otro caso deberia usarse SigningCertificateV2
	    final boolean signingCertificateV2 = true;

        final byte[] original = AOUtil.getDataFromInputStream(ptps.getSAP().getRangeStream());

        // Calculamos el MessageDigest
        final byte[] md = MessageDigest.getInstance(DEFAULT_DIGEST_ALGORITHM).digest(original);

        // Con la huella digital conocida, genero un certificado de un solo uso asociado a esa huella y con
        // los datos biometricos y hago la firma PKCS#1
        final PrivateKeyEntry pke = OtCertUtil.generateCaCertificate(
    		subjectPrincipal,
    		CryptoTrustUtil.bindBioSign(bioSign, md, trustedPartyCert),
    		signTime.getTime()
		);

        // Pre-firma CAdES
        final PdfSignResult preSign = new PdfSignResult(
            ptps.getFileID(),
            CAdESTriPhaseSigner.preSign(
                AOSignConstants.getDigestAlgorithmName(DEFAULT_DIGEST_ALGORITHM), // Algoritmo de huella digital
                null, // Datos a firmar (null por ser explicita))
                pke.getCertificateChain(), // Cadena de certificados del firmante
                AdESPolicy.buildAdESPolicy(extraParams), // Politica de firma
                signingCertificateV2, // signingCertificateV2
                md, // Valor de la huella digital del contenido
                signTime.getTime(), // Fecha de la firma (debe establecerse externamente para evitar desincronismos en la firma trifasica)
                false, // En PAdES nunca se incluye el SigningTime en la CAdES contenida
                true, // Modo PAdES
                PDF_OID,
                PDF_DESC,
                CommitmentTypeIndicationsHelper.getCommitmentTypeIndications(extraParams),
                CAdESSignerMetadataHelper.getCAdESSignerMetadata(extraParams),
                false // No omitimos la inclusion de la politica de certificacion en el SigningCertificate
            ),
            null, // Sello de tiempo
            signTime,
            extraParams
        );

        // Firma PKCS#1
        final byte[] interSign = new AOPkcs1Signer().sign(
    		preSign.getSign(),
    		DEFAULT_SIGNATURE_ALGORITHM,
    		pke.getPrivateKey(),
    		pke.getCertificateChain(),
    		extraParams
		);

        // Postfirma
        return PAdESTriPhaseSigner.postSign(
			DEFAULT_DIGEST_ALGORITHM,
			pdf,
			pke.getCertificateChain(),
			interSign,
			preSign,
			null, // SignEnhancer
			null  // EnhancerConfig (si le llega null usa los ExtraParams)
		);

	}

}
