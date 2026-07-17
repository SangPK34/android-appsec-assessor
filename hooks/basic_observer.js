/*
 * Android Security Lab observer
 * observer-version: 0.5.1
 * mode: observation-only
 */
'use strict';

const OBSERVER_VERSION = '0.5.1';
const OBSERVER_SESSION_ID = '__ANDROID_ASSESSOR_SESSION_ID__';
const TARGET_PACKAGE = '__ANDROID_ASSESSOR_PACKAGE__';
const OBSERVER_CANARY = '__ANDROID_ASSESSOR_CANARY__';

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
            return OBSERVER_CANARY.length > 0 && value.indexOf(OBSERVER_CANARY) !== -1;
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
            return OBSERVER_CANARY.length > 0 && text.indexOf(OBSERVER_CANARY) !== -1;
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

let rootCheckSequence = 0;

function sha256Text(value) {
    try {
        const JString = Java.use('java.lang.String');
        return sha256Bytes(JString.$new(String(value)).getBytes('UTF-8'));
    } catch (ignored) {
        return null;
    }
}

function rootCheckMetadata(indicatorType, indicatorValue, detected) {
    rootCheckSequence += 1;
    return {
        check_id: 'root-' + Process.id + '-' + rootCheckSequence,
        indicator_type: indicatorType,
        indicator_hash: sha256Text(indicatorValue),
        detected: detected,
        response: 'unknown',
        bypass_instrumented: false
    };
}

function fileIndicator(path) {
    const lower = String(path).toLowerCase();
    if (/(^|\/)su$/.test(lower) || lower.indexOf('/xbin/su') !== -1) {
        return 'su_file';
    }
    if (lower.indexOf('magisk') !== -1 || lower.indexOf('supersu') !== -1) {
        return 'root_manager_package';
    }
    return null;
}

function commandIndicator(command) {
    const lower = String(command).toLowerCase();
    if (lower.indexOf('getprop') !== -1) {
        return 'system_property';
    }
    if (lower.indexOf('mount') !== -1) {
        return 'mount_state';
    }
    if (/(^|\s|\/)su(\s|$)/.test(lower) || lower.indexOf('which su') !== -1) {
        return 'executable_lookup';
    }
    return null;
}

function installRootDetectionHooks() {
    try {
        const File = Java.use('java.io.File');
        File.exists.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                let path = '<unavailable>';
                try {
                    path = String(this.getAbsolutePath());
                } catch (ignored) {
                    path = '<unavailable>';
                }
                const result = overload.apply(this, arguments);
                const indicator = fileIndicator(path);
                if (indicator !== null) {
                    emitRedactedEvent(
                        'root.file_exists.' + index,
                        'root_detection',
                        'root.file_exists',
                        [rootCheckMetadata(indicator, path, Boolean(result))],
                        { type: 'boolean', value: '<redacted>' },
                        false
                    );
                }
                return result;
            };
            emitLifecycle('hook_installed', 'root.file_exists.' + index, []);
        });
    } catch (error) {
        emitLifecycle('hook_error', 'root.file_exists', [error]);
    }

    try {
        const Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                let command = '<unavailable>';
                try {
                    command = Array.isArray(args[0]) ? args[0].join(' ') : String(args[0]);
                } catch (ignored) {
                    command = '<unavailable>';
                }
                const result = overload.apply(this, args);
                const indicator = commandIndicator(command);
                if (indicator !== null) {
                    emitRedactedEvent(
                        'root.runtime_exec.' + index,
                        'root_detection',
                        'root.runtime_exec',
                        [rootCheckMetadata(indicator, command, null)],
                        { type: 'java.lang.Process', value: '<redacted>' },
                        false
                    );
                }
                return result;
            };
            emitLifecycle('hook_installed', 'root.runtime_exec.' + index, []);
        });
    } catch (error) {
        emitLifecycle('hook_error', 'root.runtime_exec', [error]);
    }

    try {
        const PackageManager = Java.use('android.app.ApplicationPackageManager');
        PackageManager.getPackageInfo.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                const packageName = args.length > 0 ? String(args[0]) : '<unavailable>';
                const lower = packageName.toLowerCase();
                const relevant = lower.indexOf('magisk') !== -1 ||
                    lower.indexOf('supersu') !== -1 || lower.indexOf('superuser') !== -1;
                try {
                    const result = overload.apply(this, args);
                    if (relevant) {
                        emitRedactedEvent(
                            'root.package_info.' + index,
                            'root_detection',
                            'root.package_info',
                            [rootCheckMetadata('root_manager_package', packageName, true)],
                            { type: 'android.content.pm.PackageInfo', value: '<redacted>' },
                            false
                        );
                    }
                    return result;
                } catch (error) {
                    if (relevant) {
                        emitRedactedEvent(
                            'root.package_info.' + index,
                            'root_detection',
                            'root.package_info',
                            [rootCheckMetadata('root_manager_package', packageName, false)],
                            null,
                            false
                        );
                    }
                    throw error;
                }
            };
            emitLifecycle('hook_installed', 'root.package_info.' + index, []);
        });
    } catch (error) {
        emitLifecycle('hook_error', 'root.package_info', [error]);
    }

    try {
        const SystemProperties = Java.use('android.os.SystemProperties');
        SystemProperties.get.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                const key = args.length > 0 ? String(args[0]) : '<unavailable>';
                const result = overload.apply(this, args);
                const value = String(result).toLowerCase();
                const relevant = key === 'ro.build.tags' || key === 'ro.debuggable' ||
                    key === 'ro.secure' || key === 'service.adb.root';
                if (relevant) {
                    const indicator = key === 'ro.build.tags' ? 'build_tags' : 'system_property';
                    const detected = (key === 'ro.build.tags' && value.indexOf('test-keys') !== -1) ||
                        (key === 'ro.debuggable' && value === '1') ||
                        (key === 'ro.secure' && value === '0') ||
                        (key === 'service.adb.root' && value === '1');
                    emitRedactedEvent(
                        'root.system_property.' + index,
                        'root_detection',
                        'root.system_property',
                        [rootCheckMetadata(indicator, key, detected)],
                        { type: 'string', length: value.length, value: '<redacted>' },
                        false
                    );
                }
                return result;
            };
            emitLifecycle('hook_installed', 'root.system_property.' + index, []);
        });
    } catch (error) {
        emitLifecycle('hook_error', 'root.system_property', [error]);
    }
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
            ['android.webkit.WebView', 'setWebContentsDebuggingEnabled', 'webview', 'webview.debugging']
        ];

        hooks.forEach(function (definition) {
            installMethod(definition[0], definition[1], definition[2], definition[3]);
        });
        installCryptoHooks();
        installRootDetectionHooks();
        emitLifecycle('observer_started', 'observer.lifecycle', []);
    });
});

rpc.exports = {
    stopObserver: function () {
        emitLifecycle('observer_stopped', 'observer.lifecycle', []);
        return true;
    }
};
