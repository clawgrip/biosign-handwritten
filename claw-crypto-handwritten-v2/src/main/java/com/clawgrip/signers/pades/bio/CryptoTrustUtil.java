package com.clawgrip.signers.pades.bio;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import es.gob.afirma.core.ciphers.AOCipherConfig;
import es.gob.afirma.core.ciphers.CipherConstants.AOCipherAlgorithm;
import es.gob.afirma.core.ciphers.CipherConstants.AOCipherBlockMode;
import es.gob.afirma.core.ciphers.CipherConstants.AOCipherPadding;
import es.gob.afirma.envelopers.cms.AOCMSEnveloper;

/** Utilidades de ligado mediante cifrado de huella y datos biom&eacute;tricos.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
final class CryptoTrustUtil {

	private static final int DEFAULT_KEY_SIZE = 128;

	private CryptoTrustUtil() {
		// No instanciable
	}

	static byte[] bindBioSign(final byte[] isoBioData,
			                  final byte[] docDigest,
			                  final X509Certificate trustedPartyCert) throws IOException {
		final byte[] content = new BioDataStructure(
			isoBioData,
			null,
			docDigest,
			PdfBioSigner.DEFAULT_DIGEST_ALGORITHM
		).getEncoded();
		try {
			return new AOCMSEnveloper().createCMSEnvelopedData(
				content,
				null,
				new AOCipherConfig(
					AOCipherAlgorithm.AES,
					AOCipherBlockMode.ECB,
					AOCipherPadding.PKCS5PADDING
				),
				new X509Certificate[] { trustedPartyCert },
				Integer.valueOf(DEFAULT_KEY_SIZE)
			);
		}
		catch (
			final CertificateEncodingException |
		    InvalidKeyException                |
		    NoSuchAlgorithmException           |
		    NoSuchPaddingException             |
		    InvalidAlgorithmParameterException |
		    IllegalBlockSizeException          |
		    BadPaddingException e
		) {
			throw new IOException(
				"Error cifrando la huella del documento junto a los datos biometricos: "+ e, e //$NON-NLS-1$
			);
		}
	}

}
