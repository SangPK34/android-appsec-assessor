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

function emitEvent(hookId, category, method, args, result, canaryMatch) {
    const payload = {
        timestamp: new Date().toISOString(),
        session_id: OBSERVER_SESSION_ID,
        package: TARGET_PACKAGE,
        pid: Process.id,
        thread_id: threadId(),
        hook_id: safeId(hookId),
        category: safeId(category),
        method: safeId(method),
        arguments_redacted: (args || []).map(summarize),
        return_value_redacted: summarize(result),
        canary_match: Boolean(canaryMatch),
        observer_version: OBSERVER_VERSION
    };
    console.log(JSON.stringify(payload));
}

function emitLifecycle(method, hookId, args) {
    emitEvent(hookId || 'observer.lifecycle', 'lifecycle', method, args || [], null, false);
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
            ['javax.crypto.Cipher', 'getInstance', 'crypto', 'cipher.get_instance'],
            ['javax.crypto.Cipher', 'init', 'crypto', 'cipher.init'],
            ['javax.crypto.Cipher', 'doFinal', 'crypto', 'cipher.do_final'],
            ['javax.crypto.spec.SecretKeySpec', '$init', 'crypto', 'key.secret_key_spec'],
            ['javax.crypto.spec.IvParameterSpec', '$init', 'crypto', 'iv.parameter_spec'],
            ['java.io.File', 'exists', 'root_detection', 'root.file_exists'],
            ['java.lang.Runtime', 'exec', 'root_detection', 'root.runtime_exec'],
            ['android.app.ApplicationPackageManager', 'getPackageInfo', 'root_detection', 'root.package_info'],
            ['android.os.SystemProperties', 'get', 'root_detection', 'root.system_property']
        ];

        hooks.forEach(function (definition) {
            installMethod(definition[0], definition[1], definition[2], definition[3]);
        });
        emitLifecycle('observer_started', 'observer.lifecycle', []);
    });
});

rpc.exports = {
    stopObserver: function () {
        emitLifecycle('observer_stopped', 'observer.lifecycle', []);
        return true;
    }
};
