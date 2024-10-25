package org.apache.seatunnel.connectors.seatunnel.elasticsearch.client;

import org.apache.seatunnel.connectors.seatunnel.elasticsearch.util.SSLUtils;

import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.KerberosCredentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.config.Lookup;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.impl.auth.SPNegoSchemeFactory;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;
import org.apache.http.ssl.SSLContexts;

import org.elasticsearch.client.RestClientBuilder;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

import javax.net.ssl.SSLContext;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;

import java.io.IOException;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

class SpnegoHttpClientConfigCallback implements RestClientBuilder.HttpClientConfigCallback {
    private static final String SUN_KRB5_LOGIN_MODULE =
            "com.sun.security.auth.module.Krb5LoginModule";
    private static final String CRED_CONF_NAME = "ESClientLoginConf";
    private static final Oid SPNEGO_OID = getSpnegoOid();

    private static Oid getSpnegoOid() {
        Oid oid = null;
        try {
            oid = new Oid("1.3.6.1.5.5.2");
        } catch (GSSException gsse) {
            throw new RuntimeException(gsse);
        }
        return oid;
    }

    private final Optional<String> username;
    private final Optional<String> password;
    private final boolean tlsVerifyCertificate;
    private final Optional<String> keystorePath;
    private final Optional<String> keystorePassword;
    private final Optional<String> truststorePath;
    private final Optional<String> truststorePassword;
    private final boolean tlsVerifyHostnames;
    private final boolean kerberosEnabled;
    private final Optional<String> userPrincipalName;
    private final Optional<String> userPassword;
    private final Optional<String> userKeytabPath;

    private LoginContext loginContext;

    public SpnegoHttpClientConfigCallback(
            Optional<String> username,
            Optional<String> password,
            boolean tlsVerifyCertificate,
            Optional<String> keystorePath,
            Optional<String> keystorePassword,
            Optional<String> truststorePath,
            Optional<String> truststorePassword,
            boolean tlsVerifyHostnames,
            boolean kerberosEnabled,
            Optional<String> userPrincipalName,
            Optional<String> userPassword,
            Optional<String> userKeytabPath) {
        this.username = username;
        this.password = password;
        this.tlsVerifyCertificate = tlsVerifyCertificate;
        this.keystorePath = keystorePath;
        this.keystorePassword = keystorePassword;
        this.truststorePath = truststorePath;
        this.truststorePassword = truststorePassword;
        this.tlsVerifyHostnames = tlsVerifyHostnames;
        this.kerberosEnabled = kerberosEnabled;
        this.userPrincipalName = userPrincipalName;
        this.userPassword = userPassword;
        this.userKeytabPath = userKeytabPath;
    }

    @Override
    public HttpAsyncClientBuilder customizeHttpClient(HttpAsyncClientBuilder httpClientBuilder) {
        if (username.isPresent()) {
            CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
            credentialsProvider.setCredentials(
                    AuthScope.ANY, new UsernamePasswordCredentials(username.get(), password.get()));
            httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider);
        }

        if (kerberosEnabled) {
            setupSpnegoAuthSchemeSupport(httpClientBuilder);
        }

        try {
            if (tlsVerifyCertificate) {
                Optional<SSLContext> sslContext =
                        SSLUtils.buildSSLContext(
                                keystorePath, keystorePassword, truststorePath, truststorePassword);
                sslContext.ifPresent(httpClientBuilder::setSSLContext);
            } else {
                SSLContext sslContext =
                        SSLContexts.custom().loadTrustMaterial(new TrustAllStrategy()).build();
                httpClientBuilder.setSSLContext(sslContext);
            }
            if (!tlsVerifyHostnames) {
                httpClientBuilder.setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return httpClientBuilder;
    }

    private void setupSpnegoAuthSchemeSupport(HttpAsyncClientBuilder httpClientBuilder) {
        final Lookup<AuthSchemeProvider> authSchemeRegistry =
                RegistryBuilder.<AuthSchemeProvider>create()
                        .register(AuthSchemes.SPNEGO, new SPNegoSchemeFactory())
                        .build();

        final GSSManager gssManager = GSSManager.getInstance();
        try {
            final GSSName gssUserPrincipalName =
                    gssManager.createName(userPrincipalName.get(), GSSName.NT_USER_NAME);
            login();
            final AccessControlContext acc = AccessController.getContext();
            final GSSCredential credential =
                    doAsPrivilegedWrapper(
                            loginContext.getSubject(),
                            (PrivilegedExceptionAction<GSSCredential>)
                                    () ->
                                            gssManager.createCredential(
                                                    gssUserPrincipalName,
                                                    GSSCredential.DEFAULT_LIFETIME,
                                                    SPNEGO_OID,
                                                    GSSCredential.INITIATE_ONLY),
                            acc);

            final KerberosCredentialsProvider credentialsProvider =
                    new KerberosCredentialsProvider();
            credentialsProvider.setCredentials(
                    new AuthScope(
                            AuthScope.ANY_HOST,
                            AuthScope.ANY_PORT,
                            AuthScope.ANY_REALM,
                            AuthSchemes.SPNEGO),
                    new KerberosCredentials(credential));
            httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider);
        } catch (GSSException e) {
            throw new RuntimeException(e);
        } catch (PrivilegedActionException e) {
            throw new RuntimeException(e.getCause());
        }
        httpClientBuilder.setDefaultAuthSchemeRegistry(authSchemeRegistry);
    }

    public synchronized LoginContext login() throws PrivilegedActionException {
        if (this.loginContext == null) {
            AccessController.doPrivileged(
                    (PrivilegedExceptionAction<Void>)
                            () -> {
                                final Subject subject =
                                        new Subject(
                                                false,
                                                Collections.singleton(
                                                        new KerberosPrincipal(
                                                                userPrincipalName.get())),
                                                Collections.emptySet(),
                                                Collections.emptySet());
                                Configuration conf = null;
                                final CallbackHandler callback;
                                if (userPassword.isPresent()) {
                                    conf = new PasswordJaasConf(userPrincipalName.get(), false);
                                    callback =
                                            new KrbCallbackHandler(
                                                    userPrincipalName.get(), userPassword.get());
                                } else if (userKeytabPath.isPresent()) {
                                    conf =
                                            new KeytabJaasConf(
                                                    userPrincipalName.get(),
                                                    userKeytabPath.get(),
                                                    false);
                                    callback = null;
                                } else {
                                    throw new RuntimeException(
                                            "user password or keytab path must be provided when kerberos is enabled");
                                }
                                loginContext = new LoginContext(CRED_CONF_NAME, subject, callback, conf);
                                loginContext.login();
                                return null;
                            });
        }
        return loginContext;
    }

    static <T> T doAsPrivilegedWrapper(
            final Subject subject,
            final PrivilegedExceptionAction<T> action,
            final AccessControlContext acc)
            throws PrivilegedActionException {
        try {
            return AccessController.doPrivileged(
                    (PrivilegedExceptionAction<T>)
                            () -> Subject.doAsPrivileged(subject, action, acc));
        } catch (PrivilegedActionException pae) {
            if (pae.getCause() instanceof PrivilegedActionException) {
                throw (PrivilegedActionException) pae.getCause();
            }
            throw pae;
        }
    }

    private static class KerberosCredentialsProvider implements CredentialsProvider {
        private AuthScope authScope;
        private Credentials credentials;

        @Override
        public void setCredentials(AuthScope authscope, Credentials credentials) {
            if (authscope
                    .getScheme()
                    .regionMatches(
                            true, 0, AuthSchemes.SPNEGO, 0, AuthSchemes.SPNEGO.length())
                    == false) {
                throw new IllegalArgumentException(
                        "Only " + AuthSchemes.SPNEGO + " auth scheme is supported in AuthScope");
            }
            this.authScope = authscope;
            this.credentials = credentials;
        }

        @Override
        public Credentials getCredentials(AuthScope authscope) {
            assert this.authScope != null && authscope != null;
            return authscope.match(this.authScope) > -1 ? this.credentials : null;
        }

        @Override
        public void clear() {
            this.authScope = null;
            this.credentials = null;
        }
    }

    private static class KrbCallbackHandler implements CallbackHandler {
        private final String principal;
        private final String password;

        KrbCallbackHandler(final String principal, final String password) {
            this.principal = principal;
            this.password = password;
        }

        public void handle(final Callback[] callbacks)
                throws IOException, UnsupportedCallbackException {
            for (Callback callback : callbacks) {
                if (callback instanceof PasswordCallback) {
                    PasswordCallback pc = (PasswordCallback) callback;
                    if (pc.getPrompt().contains(principal)) {
                        pc.setPassword(password.toCharArray());
                        break;
                    }
                }
            }
        }
    }

    private static class PasswordJaasConf extends AbstractJaasConf {

        PasswordJaasConf(final String userPrincipalName, final boolean enableDebugLogs) {
            super(userPrincipalName, enableDebugLogs);
        }

        public void addOptions(final Map<String, String> options) {
            options.put("useTicketCache", Boolean.FALSE.toString());
            options.put("useKeyTab", Boolean.FALSE.toString());
        }
    }

    private static class KeytabJaasConf extends AbstractJaasConf {
        private final String keytabFilePath;

        KeytabJaasConf(
                final String userPrincipalName,
                final String keytabFilePath,
                final boolean enableDebugLogs) {
            super(userPrincipalName, enableDebugLogs);
            this.keytabFilePath = keytabFilePath;
        }

        public void addOptions(final Map<String, String> options) {
            options.put("useKeyTab", Boolean.TRUE.toString());
            options.put("keyTab", keytabFilePath);
            options.put("doNotPrompt", Boolean.TRUE.toString());
            options.put("refreshKrb5Config", Boolean.TRUE.toString());
        }
    }

    private abstract static class AbstractJaasConf extends Configuration {
        private final String userPrincipalName;
        private final boolean enableDebugLogs;

        AbstractJaasConf(final String userPrincipalName, final boolean enableDebugLogs) {
            this.userPrincipalName = userPrincipalName;
            this.enableDebugLogs = enableDebugLogs;
        }

        @Override
        public AppConfigurationEntry[] getAppConfigurationEntry(final String name) {
            final Map<String, String> options = new HashMap<>();
            options.put("principal", userPrincipalName);
            options.put("isInitiator", Boolean.TRUE.toString());
            options.put("storeKey", Boolean.TRUE.toString());
            options.put("debug", Boolean.toString(enableDebugLogs));
            addOptions(options);
            return new AppConfigurationEntry[] {
                    new AppConfigurationEntry(
                            SUN_KRB5_LOGIN_MODULE,
                            AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                            Collections.unmodifiableMap(options))
            };
        }

        abstract void addOptions(Map<String, String> options);
    }
}
