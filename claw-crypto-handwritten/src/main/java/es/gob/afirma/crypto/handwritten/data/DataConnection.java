package es.gob.afirma.crypto.handwritten.data;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;

import es.gob.afirma.core.misc.Base64;

final class DataConnection extends URLConnection {

    DataConnection(final URL u) {
        super(u);
    }

    @Override
    public void connect() {
        this.connected = true;
    }

    @Override
    public InputStream getInputStream() throws IOException {

    	final byte[] image = Base64.decode(
			this.url.toString().replaceFirst("^.*;base64,", "")  //$NON-NLS-1$//$NON-NLS-2$
		);
        return new ByteArrayInputStream(
    		image
		);
    }

}
