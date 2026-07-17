'use strict';

function emit(event, data) {
    const payload = Object.assign({
        source: 'frida',
        event: event,
        timestamp: new Date().toISOString()
    }, data || {});
    console.log(JSON.stringify(payload));
}

setImmediate(function () {
    emit('observer_started', { java_available: Java.available });
    if (!Java.available) {
        return;
    }

    Java.perform(function () {
        try {
            const URL = Java.use('java.net.URL');
            const openConnection = URL.openConnection.overload();
            openConnection.implementation = function () {
                let protocol = '';
                let host = '';
                try {
                    protocol = String(this.getProtocol());
                    host = String(this.getHost());
                } catch (ignored) {
                    // Observation must never alter app behavior because metadata failed.
                }
                emit('url_connection', { protocol: protocol, host: host });
                return openConnection.call(this);
            };
        } catch (error) {
            emit('hook_error', { hook: 'java.net.URL', error: String(error).slice(0, 500) });
        }

        try {
            const SSLContext = Java.use('javax.net.ssl.SSLContext');
            const init = SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;',
                '[Ljavax.net.ssl.TrustManager;',
                'java.security.SecureRandom'
            );
            init.implementation = function (keyManagers, trustManagers, secureRandom) {
                emit('ssl_context_init', {
                    trust_manager_count: trustManagers === null ? 0 : trustManagers.length
                });
                return init.call(this, keyManagers, trustManagers, secureRandom);
            };
        } catch (error) {
            emit('hook_error', { hook: 'SSLContext.init', error: String(error).slice(0, 500) });
        }

        emit('java_hooks_ready', {});
    });
});
