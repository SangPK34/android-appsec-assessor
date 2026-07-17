/*
 * Android Security Lab observer
 * observer-version: 0.5.1
 * mode: observation-only
 */
'use strict';

const OBSERVER_VERSION = '0.5.1';
const OBSERVER_SESSION_ID = '__ANDROID_ASSESSOR_SESSION_ID__';
const TARGET_PACKAGE = '__ANDROID_ASSESSOR_PACKAGE__';
const CANARY_PREFIX = 'THESIS_CANARY_';

function safeId(value) {
    return String(value).replace(/[^A-Za-z0-9._:-]/g, '_').slice(0, 128);
}

function threadId() {
    try {
        return Process.getCurrentThreadId();
    } catch (ignored) {
        return 0;
    }
}

function containsCanary(value, depth) {
    if (depth > 2 || value === null || value === undefined) {
        return false;
    }
    try {
        if (typeof value === 'string') {
            return value.indexOf(CANARY_PREFIX) !== -1;
        }
        if (Array.isArray(value)) {
            return value.some(function (item) { return containsCanary(item, depth + 1); });
        }
        if (typeof value.length === 'number' && value.length >= 0 && value.length <= 4096) {
            let text = '';
            for (let index = 0; index < value.length; index += 1) {
                if (typeof value[index] !== 'number') {
                    return false;
                }
                text += String.fromCharCode(value[index] & 0xff);
            }
            return text.indexOf(CANARY_PREFIX) !== -1;
        }
        return false;
    } catch (ignored) {
        return false;
    }
}

function summarize(value) {
    if (value === null || value === undefined) {
        return null;
    }
    try {
        if (typeof value === 'string') {
            return { type: 'string', length: value.length, value: '<redacted>' };
        }
        if (typeof value === 'number' || typeof value === 'boolean') {
            return { type: typeof value, value: '<redacted>' };
        }
        if (Array.isArray(value)) {
            return { type: 'array', length: value.length, value: '<redacted>' };
        }
        const className = typeof value.$className === 'string' ? value.$className : 'object';
        const length = typeof value.length === 'number' ? value.length : null;
        return { type: safeId(className), length: length, value: '<redacted>' };
    } catch (ignored) {
        return { type: 'unknown', value: '<redacted>' };
    }
}

function emitRedactedEvent(
    hookId,
    category,
    method,
    argumentsRedacted,
    returnValueRedacted,
    canaryMatch
) {
    const payload = {
        timestamp: new Date().toISOString(),
        session_id: OBSERVER_SESSION_ID,
        package: TARGET_PACKAGE,
        pid: Process.id,
        thread_id: threadId(),
        hook_id: safeId(hookId),
        category: safeId(category),
        method: safeId(method),
        arguments_redacted: argumentsRedacted || [],
        return_value_redacted: returnValueRedacted,
        canary_match: Boolean(canaryMatch),
        observer_version: OBSERVER_VERSION
    };
    console.log(JSON.stringify(payload));
}

function emitEvent(hookId, category, method, args, result, canaryMatch) {
    emitRedactedEvent(
        hookId,
        category,
        method,
        (args || []).map(summarize),
        summarize(result),
        canaryMatch
    );
}

function emitLifecycle(method, hookId, args) {
    emitEvent(hookId || 'observer.lifecycle', 'lifecycle', method, args || [], null, false);
}

let cryptoSequence = 0;
const cipherState = {};

function safeTransformation(value) {
    try {
        const text = String(value);
        return /^[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+){0,2}$/.test(text)
            ? text
            : '<redacted>';
    } catch (ignored) {
        return '<redacted>';
    }
}

function sha256Bytes(value) {
    if (value === null || value === undefined) {
        return null;
    }
    try {
        const MessageDigest = Java.use('java.security.MessageDigest');
        const digest = MessageDigest.getInstance('SHA-256').digest(value);
        let output = '';
        for (let index = 0; index < digest.length; index += 1) {
            output += ('0' + (digest[index] & 0xff).toString(16)).slice(-2);
        }
        return output;
    } catch (ignored) {
        return null;
    }
}

function byteMetadata(value, hashName) {
    if (value === null || value === undefined || typeof value.length !== 'number') {
        return { length: null };
    }
    const output = { length: value.length };
    output[hashName] = sha256Bytes(value);
    return output;
}

function cipherKey(cipher) {
    try {
        return String(cipher.hashCode());
    } catch (ignored) {
        cryptoSequence += 1;
        return 'fallback-' + cryptoSequence;
    }
}

function purposeName(value) {
    return { 1: 'encrypt', 2: 'decrypt', 3: 'wrap', 4: 'unwrap' }[value] || 'unknown';
}

function installCryptoHooks() {
    try {
        const Cipher = Java.use('javax.crypto.Cipher');
        Cipher.getInstance.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                const result = overload.apply(this, args);
                emitRedactedEvent(
                    'cipher.get_instance.' + index,
                    'crypto',
                    'cipher.get_instance',
                    [{ transformation: safeTransformation(args[0]) }],
                    { type: 'javax.crypto.Cipher', value: '<redacted>' },
                    false
                );
                return result;
            };
            emitLifecycle('hook_installed', 'cipher.get_instance.' + index, []);
        });

        Cipher.init.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                let result;
                try {
                    result = overload.apply(this, args);
                } catch (error) {
                    emitLifecycle('hook_error', 'cipher.init.' + index, [error]);
                    throw error;
                }
                const stateKey = cipherKey(this);
                cryptoSequence += 1;
                const operationId = 'crypto-' + Process.id + '-' + cryptoSequence;
                let keyBytes = null;
                try {
                    keyBytes = args.length > 1 && args[1] !== null ? args[1].getEncoded() : null;
                } catch (ignored) {
                    keyBytes = null;
                }
                let ivBytes = null;
                try {
                    ivBytes = this.getIV();
                } catch (ignored) {
                    ivBytes = null;
                }
                const keyMeta = byteMetadata(keyBytes, 'key_sha256');
                const ivMeta = byteMetadata(ivBytes, 'iv_sha256');
                const state = {
                    operation_id: operationId,
                    transformation: safeTransformation(this.getAlgorithm()),
                    purpose: purposeName(args[0]),
                    executed: false,
                    key_length_bits: keyMeta.length === null ? null : keyMeta.length * 8,
                    key_sha256: keyMeta.key_sha256 || null,
                    iv_sha256: ivMeta.iv_sha256 || null,
                    iv_source: 'unknown',
                    key_origin: 'unknown'
                };
                cipherState[stateKey] = state;
                emitRedactedEvent(
                    'cipher.init.' + index,
                    'crypto',
                    'cipher.init',
                    [state],
                    null,
                    false
                );
                return result;
            };
            emitLifecycle('hook_installed', 'cipher.init.' + index, []);
        });

        Cipher.doFinal.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                let result;
                try {
                    result = overload.apply(this, args);
                } catch (error) {
                    emitLifecycle('hook_error', 'cipher.do_final.' + index, [error]);
                    throw error;
                }
                const stateKey = cipherKey(this);
                const state = cipherState[stateKey] || {
                    operation_id: 'crypto-' + Process.id + '-unknown',
                    transformation: safeTransformation(this.getAlgorithm()),
                    purpose: 'unknown',
                    key_length_bits: null,
                    key_sha256: null,
                    iv_sha256: null,
                    iv_source: 'unknown',
                    key_origin: 'unknown'
                };
                state.executed = true;
                const input = args.length > 0 ? args[0] : null;
                const inputMeta = byteMetadata(input, 'input_sha256');
                const outputMeta = byteMetadata(result, 'output_sha256');
                emitRedactedEvent(
                    'cipher.do_final.' + index,
                    'crypto',
                    'cipher.do_final',
                    [state, inputMeta],
                    outputMeta,
                    containsCanary(input, 0) || containsCanary(result, 0)
                );
                return result;
            };
            emitLifecycle('hook_installed', 'cipher.do_final.' + index, []);
        });
    } catch (error) {
        emitLifecycle('hook_error', 'cipher.observer', [error]);
    }

    installMethod('javax.crypto.spec.SecretKeySpec', '$init', 'crypto', 'key.secret_key_spec');
    installMethod('javax.crypto.spec.IvParameterSpec', '$init', 'crypto', 'iv.parameter_spec');
}

function installMethod(className, methodName, category, hookId) {
    try {
        const Klass = Java.use(className);
        const method = Klass[methodName];
        if (!method || !method.overloads) {
            throw new Error('method unavailable');
        }
        method.overloads.forEach(function (overload, index) {
            const installedId = safeId(hookId + '.' + index);
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                const canary = args.some(function (item) { return containsCanary(item, 0); });
                let result;
                try {
                    result = overload.apply(this, args);
                } catch (error) {
                    emitLifecycle('hook_error', installedId, [error]);
                    throw error;
                }
                emitEvent(
                    installedId,
                    category,
                    safeId(className + '.' + methodName),
                    args,
                    result,
                    canary || containsCanary(result, 0)
                );
                return result;
            };
            emitLifecycle('hook_installed', installedId, []);
        });
    } catch (error) {
        emitLifecycle('hook_error', hookId, [error]);
    }
}

emitLifecycle('observer_loading', 'observer.lifecycle', []);

setImmediate(function () {
    if (!Java.available) {
        emitLifecycle('hook_error', 'observer.java', ['Java runtime unavailable']);
        return;
    }

    Java.perform(function () {
        const hooks = [
            ['android.app.SharedPreferencesImpl', 'getString', 'storage', 'preferences.get_string'],
            ['android.app.SharedPreferencesImpl$EditorImpl', 'putString', 'storage', 'preferences.put_string'],
            ['android.database.sqlite.SQLiteDatabase', 'rawQuery', 'storage', 'sqlite.raw_query'],
            ['android.database.sqlite.SQLiteDatabase', 'query', 'storage', 'sqlite.query'],
            ['android.database.sqlite.SQLiteDatabase', 'execSQL', 'storage', 'sqlite.exec_sql'],
            ['java.io.FileInputStream', '$init', 'storage', 'file.read'],
            ['java.io.FileOutputStream', '$init', 'storage', 'file.write'],
            ['android.util.Log', 'd', 'logging', 'log.debug'],
            ['android.util.Log', 'i', 'logging', 'log.info'],
            ['android.util.Log', 'w', 'logging', 'log.warn'],
            ['android.util.Log', 'e', 'logging', 'log.error'],
            ['javax.net.ssl.SSLContext', 'init', 'tls', 'trust.ssl_context_init'],
            ['javax.net.ssl.TrustManagerFactory', 'getTrustManagers', 'tls', 'trust.manager_factory'],
            ['okhttp3.OkHttpClient', 'newCall', 'network', 'okhttp.new_call'],
            ['android.webkit.WebView', 'loadUrl', 'webview', 'webview.load_url'],
            ['android.webkit.WebView', 'addJavascriptInterface', 'webview', 'webview.javascript_interface'],
            ['android.webkit.WebView', 'setWebContentsDebuggingEnabled', 'webview', 'webview.debugging'],
            ['java.io.File', 'exists', 'root_detection', 'root.file_exists'],
            ['java.lang.Runtime', 'exec', 'root_detection', 'root.runtime_exec'],
            ['android.app.ApplicationPackageManager', 'getPackageInfo', 'root_detection', 'root.package_info'],
            ['android.os.SystemProperties', 'get', 'root_detection', 'root.system_property']
        ];

        hooks.forEach(function (definition) {
            installMethod(definition[0], definition[1], definition[2], definition[3]);
        });
        installCryptoHooks();
        emitLifecycle('observer_started', 'observer.lifecycle', []);
    });
});

rpc.exports = {
    stopObserver: function () {
        emitLifecycle('observer_stopped', 'observer.lifecycle', []);
        return true;
    }
};
