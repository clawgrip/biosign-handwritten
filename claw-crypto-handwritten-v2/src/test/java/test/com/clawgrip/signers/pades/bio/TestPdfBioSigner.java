package test.com.clawgrip.signers.pades.bio;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Properties;

import com.clawgrip.signers.pades.bio.PdfBioSigner;

import es.gob.afirma.core.AOException;
import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.signers.pades.InvalidPdfException;

/** Pruebas del Firmador biom&eacute;trico de PDF.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class TestPdfBioSigner {

	private final static String TEST_FILE = "/TEST_PDF.pdf"; //$NON-NLS-1$
	private final static byte[] PDF;
	static {
		try {
			PDF = AOUtil.getDataFromInputStream(PdfBioSigner.class.getResourceAsStream(TEST_FILE));
		}
		catch (final IOException e) {
			throw new IllegalStateException(e);
		}
	}

    private static final String CERT_PATH = "PFActivoFirSHA256.pfx"; //$NON-NLS-1$
    private static final String CERT_PASS = "12341234"; //$NON-NLS-1$
    private static final X509Certificate THIRD_PARTY_CERT;
    static {
    	try {
			final KeyStore ks = KeyStore.getInstance("PKCS12"); //$NON-NLS-1$
			ks.load(ClassLoader.getSystemResourceAsStream(CERT_PATH), CERT_PASS.toCharArray());
			THIRD_PARTY_CERT = (X509Certificate) ks.getCertificate(ks.aliases().nextElement());
    	}
    	catch (final Exception e) {
			throw new IllegalStateException(e);
		}

    }

	/** Main para pruebas.
	 * @param args No se usa.
	 * @throws AOException En cualquier otro error.
	 * @throws IOException Si hay problemas en la lectura o escritura de datos.
	 * @throws InvalidPdfException Si el PDF est&aacute; corrupto o no es un PDF.
	 * @throws CertificateException Si hay problemas generando el certificado.
	 * @throws NoSuchAlgorithmException Si el entorno de ejecuci&oacute;n no soporta alg&uacute;n algoritmo necesario. */
	public static void main(final String[] args) throws InvalidPdfException,
	                                                    IOException,
	                                                    AOException,
	                                                    CertificateException,
	                                                    NoSuchAlgorithmException {

		final String subjectPrincipal = "CN=Tomás García-Merás"; //$NON-NLS-1$
		final byte[] bioSign = "testdata".getBytes(); //$NON-NLS-1$
		final Properties extraParams = new Properties();

		final byte[] signedPdf = PdfBioSigner.bioSignPdf(
			PDF,
			extraParams,
			subjectPrincipal,
			bioSign,
			THIRD_PARTY_CERT
		);
        try (
    		final OutputStream fos = new FileOutputStream(File.createTempFile("BIOBIOBIO_", ".pdf")); //$NON-NLS-1$ //$NON-NLS-2$
		) {
        	fos.write(signedPdf);
        	fos.flush();
        	fos.close();
        }
	}

}
