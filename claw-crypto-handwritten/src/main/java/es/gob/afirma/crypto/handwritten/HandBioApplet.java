package es.gob.afirma.crypto.handwritten;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.logging.Logger;

import javax.swing.JOptionPane;

import es.gob.afirma.core.misc.Base64;
import es.gob.afirma.core.ui.AOUIFactory;
import netscape.javascript.JSObject;

/** Applet para abrir la aplicaci&oacute;n de firma en tableta.
 * @author Astrid Idoate. */
@SuppressWarnings("deprecation")
public final class HandBioApplet extends javax.swing.JApplet {

	private static final long serialVersionUID = 4423801785743703642L;
	String base64XmlTask = null;
	static final Logger LOGGER = Logger.getLogger("es.gob.afirma"); //$NON-NLS-1$

	@Override
	public void init() {

		setFocusable(false);

		final JSObject window = JSObject.getWindow(this);

		final String xmlTask =  getParameter("xmltask"); //$NON-NLS-1$
		if (xmlTask == null || "".equals(xmlTask)) { //$NON-NLS-1$
			AOUIFactory.showErrorMessage(
				this,
				HandwrittenMessages.getString("HandBioApplet.5"), //$NON-NLS-1$
				HandwrittenMessages.getString("HandBioApplet.2"), //$NON-NLS-1$
				JOptionPane.ERROR_MESSAGE
			);
			LOGGER.severe("No se ha indicado una tarea de firma en la carga del Applet"); //$NON-NLS-1$
			return;
		}
		try {
			this.base64XmlTask = new String(Base64.decode(xmlTask));
		}
		catch (final Exception e) {
			LOGGER.severe("Error decodifciando el parametro XML: " + e); //$NON-NLS-1$
			AOUIFactory.showErrorMessage(
				this,
				HandwrittenMessages.getString("HandBioApplet.1"), //$NON-NLS-1$
				HandwrittenMessages.getString("HandBioApplet.2"), //$NON-NLS-1$
				JOptionPane.ERROR_MESSAGE
			);
			return;
		}

		LOGGER.info("Leido parametro de firma: " + this.base64XmlTask); //$NON-NLS-1$

		if (this.base64XmlTask == null || "".equals(this.base64XmlTask)) { //$NON-NLS-1$
			// Dialogo
			LOGGER.severe("No se ha indicado una tarea de firma"); //$NON-NLS-1$
			AOUIFactory.showErrorMessage(this, HandwrittenMessages.getString("HandBioApplet.1"), HandwrittenMessages.getString("HandBioApplet.2"),JOptionPane.ERROR_MESSAGE); //$NON-NLS-1$ //$NON-NLS-2$
			return;
		}

		LOGGER.info("Inicio BioSignerRunner"); //$NON-NLS-1$
		AccessController.doPrivileged(
	     new PrivilegedAction<Void>() {
		    @Override
			public Void run() {
		    	initProcess(
		    		window
		    	);
		    	return null;
            }
		  }
		);
	}

	void initProcess(
			final JSObject windowsRequest
			) {

		LOGGER.info("Iniciando aplicacion..."); //$NON-NLS-1$

		try {
			new BioSignerRunner(this.base64XmlTask, windowsRequest).show();
		}
		catch (final IllegalArgumentException e) {
			LOGGER.severe("La tarea de firma no es correcta: " + e); //$NON-NLS-1$
			AOUIFactory.showErrorMessage(this, HandwrittenMessages.getString("HandBioApplet.4"), HandwrittenMessages.getString("HandBioApplet.2"), JOptionPane.ERROR_MESSAGE); //$NON-NLS-1$ //$NON-NLS-2$
		}
    	catch(final Exception e) {
			LOGGER.severe("Error al lanzar la aplicacion de firma en tableta. " + e); //$NON-NLS-1$
			AOUIFactory.showErrorMessage(this, HandwrittenMessages.getString("HandBioApplet.3"), HandwrittenMessages.getString("HandBioApplet.2"), JOptionPane.ERROR_MESSAGE); //$NON-NLS-1$ //$NON-NLS-2$
		}

	}
}
