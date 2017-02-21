package org.apache.activemq.artemis.plugins.security.jaas;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.security.Principal;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.apache.activemq.artemis.spi.core.security.jaas.RolePrincipal;
import org.apache.activemq.artemis.spi.core.security.jaas.UserPrincipal;
import org.jboss.logging.Logger;

public class OAuth2LoginModule implements LoginModule {

	private static final Logger logger = Logger.getLogger(OAuth2LoginModule.class);

	private static final String OAUTH2_TOKEN = "org.apache.activemq.jaas.oauth2.token";
	private static final String OAUTH2_ROLE = "org.apache.activemq.jaas.oauth2.role";
	private static final String OAUTH2_URL = "org.apache.activemq.jaas.oauth2.oauth2url";

	private boolean debug;

	private String userName;
	private String roleName = "oauth2-role";
	private String oauth2URL = "oauth2-url";

	private Subject subject;
	private CallbackHandler callbackHandler;

	private final Set<Principal> principals = new HashSet<>();

	private boolean loginSucceeded;

	@Override
	public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
			Map<String, ?> options) {

		this.subject = subject;
		this.callbackHandler = callbackHandler;

		debug = "true".equalsIgnoreCase((String) options.get("debug"));

		if (options.get(OAUTH2_ROLE) != null) {
			roleName = (String) options.get(OAUTH2_ROLE);
		}
		if (options.get(OAUTH2_URL) != null) {
			oauth2URL = (String) options.get(OAUTH2_URL);
		}

		if (debug) {
			logger.debug("Initialized debug=" + debug + " guestGroup=" + roleName + " url="
					+ oauth2URL);
		}

	}

	@Override
	public boolean login() throws LoginException {
		loginSucceeded = true;

		Callback[] callbacks = new Callback[1];
		callbacks[0] = new NameCallback("User name");

		try {
			callbackHandler.handle(callbacks);
		} catch (IOException | UnsupportedCallbackException e) {
			throw (LoginException) new LoginException().initCause(e);
		}
		
		userName = ((NameCallback) callbacks[0]).getName();
		
		if (null == userName) 
			loginSucceeded = false;

		String newUrl = "https://" + oauth2URL + "?access_token=" + userName;
		logger.debug("THis is the URL: " + newUrl);

		final boolean eligible = determineAuthorization(newUrl);

		if (eligible) {
			principals.add(new UserPrincipal(userName));
			principals.add(new RolePrincipal(roleName));
		} else {
			loginSucceeded = false;
		}

		if (debug) {
			logger.debug("Token login " + loginSucceeded);
		}
		return loginSucceeded;
	}

	@Override
	public boolean commit() throws LoginException {
		if (loginSucceeded) {
			logger.debug("Commit::LoginSucceeded");
			subject.getPrincipals().addAll(principals);
		}

		if (debug) {
			logger.debug("commit: " + loginSucceeded);
		}
		return loginSucceeded;
	}

	@Override
	public boolean abort() throws LoginException {

		if (debug) {
			logger.debug("abort");
		}
		return true;
	}

	@Override
	public boolean logout() throws LoginException {
		subject.getPrincipals().removeAll(principals);
		if (debug) {
			logger.debug("logout");
		}
		return true;
	}

	private boolean determineAuthorization(String url) {

		boolean returnableBoolean = true;
		try {

			URL myURL = new URL(url);
			URLConnection connection = myURL.openConnection();

			connection.setDoOutput(true);

			BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
			String inputLine;
			while ((inputLine = in.readLine()) != null) {
				logger.debug("InputLine: " + inputLine);

				// Should not be executed if credentials are bad since 401
				// Exception is thrown.
				// String matching login shown as example.
				if (inputLine.contains("Bad credentials")) {
					returnableBoolean = false;
				}
			}
			in.close();

		} catch (Exception e) {

			// If token is bad, 401 Exception is caught here

			returnableBoolean = false;
			logger.debug("Oauth2Exception: " + e.getMessage());
		}

		return returnableBoolean;
	}

}
