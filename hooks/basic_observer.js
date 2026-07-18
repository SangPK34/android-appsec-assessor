/*
 * Android Security Lab observer
 * observer-version: 0.6.0
 * mode: observation-only
 */
'use strict';

const OBSERVER_VERSION = '0.6.0';
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

function containsExactCanaryText(value) {
    if (OBSERVER_CANARY.length === 0 || typeof value !== 'string') {
        return false;
    }
    let offset = value.indexOf(OBSERVER_CANARY);
    while (offset !== -1) {
        const before = offset === 0 ? '' : value[offset - 1];
        const afterOffset = offset + OBSERVER_CANARY.length;
        const after = afterOffset >= value.length ? '' : value[afterOffset];
        if (!/[A-Za-z0-9_]/.test(before) && !/[A-Za-z0-9_]/.test(after)) {
            return true;
        }
        offset = value.indexOf(OBSERVER_CANARY, offset + 1);
    }
    return false;
}

function knownJavaText(value) {
    if (value === null || value === undefined) {
        return null;
    }
    let className = '';
    try {
        className = String(value.$className || value.getClass().getName());
    } catch (ignored) {
        return null;
    }
    if ([
        'java.lang.String',
        'java.lang.StringBuilder',
        'java.lang.StringBuffer',
        'android.text.SpannableString',
        'android.text.SpannableStringBuilder',
        'android.text.SpannedString'
    ].indexOf(className) === -1) {
        return null;
    }
    try {
        const text = String(value);
        return text.length <= 4096 ? text : null;
    } catch (ignored) {
        return null;
    }
}

function containsCanary(value, depth) {
    if (depth > 2 || value === null || value === undefined) {
        return false;
    }
    try {
        if (typeof value === 'string') {
            return containsExactCanaryText(value);
        }
        if (Array.isArray(value)) {
            return value.some(function (item) { return containsCanary(item, depth + 1); });
        }
        const knownText = knownJavaText(value);
        if (knownText !== null) {
            return containsExactCanaryText(knownText);
        }
        if (typeof value.length === 'number' && value.length >= 0 && value.length <= 4096) {
            let text = '';
            for (let index = 0; index < value.length; index += 1) {
                if (typeof value[index] !== 'number') {
                    return false;
                }
                text += String.fromCharCode(value[index] & 0xff);
            }
            return containsExactCanaryText(text);
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
const digestState = {};
const macState = {};
const secureRandomOutputs = {};
const weakRandomOutputs = {};
const webViewSettings = {};
const preferenceEditors = {};
const contentValues = {};
const fileStreams = {};
const clipboardValues = {};
const tlsInstrumentedClasses = {};
const webViewClientInstrumentedClasses = {};
let internalDigestDepth = 0;
const MAX_TRACKED_OBJECTS = 512;
const MAX_RANDOM_FINGERPRINT_BYTES = 65536;

function boundedPut(target, key, value) {
    if (key === null || key === undefined) {
        return;
    }
    if (!Object.prototype.hasOwnProperty.call(target, key) &&
        Object.keys(target).length >= MAX_TRACKED_OBJECTS) {
        delete target[Object.keys(target)[0]];
    }
    target[key] = value;
}

function objectId(value, prefix) {
    if (value === null || value === undefined) {
        return null;
    }
    try {
        const System = Java.use('java.lang.System');
        return safeId(prefix + '-' + String(System.identityHashCode(value)));
    } catch (ignored) {
        return null;
    }
}

function containsCanaryByteRange(value, offset, length) {
    if (value === null || value === undefined ||
        typeof value.length !== 'number' ||
        typeof offset !== 'number' || typeof length !== 'number') {
        return false;
    }
    const start = Math.max(0, Math.floor(offset));
    const end = Math.min(value.length, start + Math.max(0, Math.floor(length)));
    if (end <= start || end - start > 4096) {
        return false;
    }
    let text = '';
    try {
        for (let index = start; index < end; index += 1) {
            text += String.fromCharCode(value[index] & 0xff);
        }
    } catch (ignored) {
        return false;
    }
    return containsExactCanaryText(text);
}

function bundleContainsCanary(bundle) {
    if (bundle === null || bundle === undefined) {
        return false;
    }
    try {
        const iterator = bundle.keySet().iterator();
        let inspected = 0;
        while (iterator.hasNext() && inspected < 64) {
            const key = iterator.next();
            if (containsCanary(bundle.get(key), 0)) {
                return true;
            }
            inspected += 1;
        }
    } catch (ignored) {
        return false;
    }
    return false;
}

function intentSinkMetadata(intent, deliveryKind) {
    let matched = false;
    let targetScope = 'implicit';
    try {
        const data = intent.getDataString();
        matched = data !== null && containsExactCanaryText(String(data));
    } catch (ignored) {
        matched = false;
    }
    try {
        matched = matched || bundleContainsCanary(intent.getExtras());
    } catch (ignored) {
        // Keep the already established data-URI result.
    }
    try {
        let targetPackage = intent.getPackage();
        if (targetPackage === null) {
            const component = intent.getComponent();
            targetPackage = component === null ? null : component.getPackageName();
        }
        if (targetPackage !== null) {
            targetScope = String(targetPackage) === TARGET_PACKAGE ?
                'target_package' : 'other_package';
        }
    } catch (ignored) {
        targetScope = 'unknown';
    }
    const implicitBoundary = targetScope === 'implicit';
    return {
        matched: matched,
        metadata: {
            sink_type: deliveryKind.indexOf('broadcast') !== -1 ? 'broadcast' : 'intent',
            delivery_kind: safeId(deliveryKind),
            target_scope: targetScope,
            boundary_exposed: targetScope === 'other_package' || implicitBoundary,
            exposure_confidence: targetScope === 'other_package' ?
                'clear' : implicitBoundary ? 'candidate' : 'unknown',
            persisted: false
        }
    };
}

function notificationContainsCanary(notification) {
    if (notification === null || notification === undefined) {
        return false;
    }
    try {
        let extras = notification.extras;
        if (extras !== null && extras !== undefined && extras.value !== undefined) {
            extras = extras.value;
        }
        return bundleContainsCanary(extras);
    } catch (ignored) {
        return false;
    }
}

function allZeroBytes(value) {
    if (value === null || value === undefined || typeof value.length !== 'number') {
        return null;
    }
    if (value.length === 0 || value.length > 65536) {
        return null;
    }
    try {
        for (let index = 0; index < value.length; index += 1) {
            if ((value[index] & 0xff) !== 0) {
                return false;
            }
        }
        return true;
    } catch (ignored) {
        return null;
    }
}

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
        internalDigestDepth += 1;
        const MessageDigest = Java.use('java.security.MessageDigest');
        const digest = MessageDigest.getInstance('SHA-256').digest(value);
        let output = '';
        for (let index = 0; index < digest.length; index += 1) {
            output += ('0' + (digest[index] & 0xff).toString(16)).slice(-2);
        }
        return output;
    } catch (ignored) {
        return null;
    } finally {
        internalDigestDepth = Math.max(0, internalDigestDepth - 1);
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

function byteFingerprint(value) {
    const metadata = byteMetadata(value, 'sha256');
    return metadata.sha256 || null;
}

function safeAlgorithm(value) {
    return safeTransformation(value);
}

function cryptoState(operationKind, transformation, purpose) {
    cryptoSequence += 1;
    return {
        operation_id: 'crypto-' + Process.id + '-' + cryptoSequence,
        operation_kind: operationKind,
        transformation: safeAlgorithm(transformation),
        purpose: purpose,
        executed: false,
        key_length_bits: null,
        key_sha256: null,
        iv_sha256: null,
        iv_source: 'unknown',
        key_origin: 'unknown',
        iv_length: null,
        iv_zero: null,
        salt_length: null,
        iteration_count: null,
        call_sequence: []
    };
}

function cipherKey(cipher) {
    const identity = objectId(cipher, 'cipher');
    if (identity !== null) {
        return identity;
    }
    cryptoSequence += 1;
    return 'fallback-' + cryptoSequence;
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
                const state = cryptoState(
                    'cipher',
                    this.getAlgorithm(),
                    purposeName(args[0])
                );
                state.key_length_bits = keyMeta.length === null ? null : keyMeta.length * 8;
                state.key_sha256 = keyMeta.key_sha256 || null;
                state.key_origin = state.key_sha256 && weakRandomOutputs[state.key_sha256] ?
                    'weak_random' : state.key_sha256 && secureRandomOutputs[state.key_sha256] ?
                        'generated' : 'unknown';
                state.iv_sha256 = ivMeta.iv_sha256 || null;
                state.iv_length = ivMeta.length;
                state.iv_zero = allZeroBytes(ivBytes);
                state.iv_source = ivBytes === null ? 'none' :
                    weakRandomOutputs[state.iv_sha256] ? 'weak_random' :
                        secureRandomOutputs[state.iv_sha256] ? 'random' : 'unknown';
                state.call_sequence = ['cipher.get_instance', 'cipher.init'];
                boundedPut(cipherState, stateKey, state);
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
                    operation_kind: 'cipher',
                    transformation: safeTransformation(this.getAlgorithm()),
                    purpose: 'unknown',
                    executed: false,
                    key_length_bits: null,
                    key_sha256: null,
                    iv_sha256: null,
                    iv_source: 'unknown',
                    key_origin: 'unknown',
                    iv_length: null,
                    iv_zero: null,
                    salt_length: null,
                    iteration_count: null,
                    call_sequence: ['cipher.do_final']
                };
                state.executed = true;
                if (state.call_sequence.indexOf('cipher.do_final') === -1) {
                    state.call_sequence.push('cipher.do_final');
                }
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

function installDigestHooks() {
    try {
        const MessageDigest = Java.use('java.security.MessageDigest');
        MessageDigest.getInstance.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                const result = overload.apply(this, args);
                if (internalDigestDepth > 0) {
                    return result;
                }
                const state = cryptoState('digest', args[0], 'digest');
                state.call_sequence = ['digest.get_instance'];
                boundedPut(digestState, objectId(result, 'digest'), state);
                emitRedactedEvent(
                    'digest.get_instance.' + index,
                    'crypto',
                    'digest.get_instance',
                    [state],
                    null,
                    false
                );
                return result;
            };
            emitLifecycle('hook_installed', 'digest.get_instance.' + index, []);
        });
        MessageDigest.update.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                const result = overload.apply(this, args);
                if (internalDigestDepth > 0) {
                    return result;
                }
                const key = objectId(this, 'digest');
                const state = digestState[key];
                if (state) {
                    state.canary_match = Boolean(state.canary_match) ||
                        args.some(function (item) { return containsCanary(item, 0); });
                    if (state.call_sequence.indexOf('digest.update') === -1) {
                        state.call_sequence.push('digest.update');
                    }
                }
                return result;
            };
            emitLifecycle('hook_installed', 'digest.update.' + index, []);
        });
        MessageDigest.digest.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                const result = overload.apply(this, args);
                if (internalDigestDepth > 0) {
                    return result;
                }
                const key = objectId(this, 'digest');
                const state = digestState[key] || cryptoState(
                    'digest', this.getAlgorithm(), 'digest'
                );
                state.executed = true;
                state.canary_match = Boolean(state.canary_match) ||
                    args.some(function (item) { return containsCanary(item, 0); });
                if (state.call_sequence.indexOf('digest.digest') === -1) {
                    state.call_sequence.push('digest.digest');
                }
                emitRedactedEvent(
                    'digest.digest.' + index,
                    'crypto',
                    'digest.digest',
                    [state],
                    byteMetadata(result, 'output_sha256'),
                    Boolean(state.canary_match)
                );
                delete digestState[key];
                return result;
            };
            emitLifecycle('hook_installed', 'digest.digest.' + index, []);
        });
    } catch (error) {
        emitLifecycle('hook_error', 'digest.observer', [error]);
    }
}

function installMacHooks() {
    try {
        const Mac = Java.use('javax.crypto.Mac');
        Mac.getInstance.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                const result = overload.apply(this, args);
                const state = cryptoState('mac', args[0], 'sign');
                state.call_sequence = ['mac.get_instance'];
                boundedPut(macState, objectId(result, 'mac'), state);
                emitRedactedEvent(
                    'mac.get_instance.' + index,
                    'crypto',
                    'mac.get_instance',
                    [state],
                    null,
                    false
                );
                return result;
            };
            emitLifecycle('hook_installed', 'mac.get_instance.' + index, []);
        });
        Mac.init.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                const result = overload.apply(this, args);
                const key = objectId(this, 'mac');
                const state = macState[key] || cryptoState(
                    'mac', this.getAlgorithm(), 'sign'
                );
                let keyBytes = null;
                try {
                    keyBytes = args[0] !== null ? args[0].getEncoded() : null;
                } catch (ignored) {
                    keyBytes = null;
                }
                const keyMeta = byteMetadata(keyBytes, 'key_sha256');
                state.key_length_bits = keyMeta.length === null ? null : keyMeta.length * 8;
                state.key_sha256 = keyMeta.key_sha256 || null;
                if (state.call_sequence.indexOf('mac.init') === -1) {
                    state.call_sequence.push('mac.init');
                }
                boundedPut(macState, key, state);
                return result;
            };
            emitLifecycle('hook_installed', 'mac.init.' + index, []);
        });
        Mac.doFinal.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                const result = overload.apply(this, args);
                const key = objectId(this, 'mac');
                const state = macState[key] || cryptoState(
                    'mac', this.getAlgorithm(), 'sign'
                );
                state.executed = true;
                state.canary_match = Boolean(state.canary_match) ||
                    args.some(function (item) { return containsCanary(item, 0); });
                if (state.call_sequence.indexOf('mac.do_final') === -1) {
                    state.call_sequence.push('mac.do_final');
                }
                emitRedactedEvent(
                    'mac.do_final.' + index,
                    'crypto',
                    'mac.do_final',
                    [state],
                    byteMetadata(result, 'output_sha256'),
                    Boolean(state.canary_match)
                );
                delete macState[key];
                return result;
            };
            emitLifecycle('hook_installed', 'mac.do_final.' + index, []);
        });
    } catch (error) {
        emitLifecycle('hook_error', 'mac.observer', [error]);
    }
}

function installPbeHooks() {
    try {
        const PBEKeySpec = Java.use('javax.crypto.spec.PBEKeySpec');
        PBEKeySpec.$init.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                const result = overload.apply(this, args);
                const state = cryptoState('pbe', 'PBE', 'derive');
                state.executed = true;
                state.salt_length = args.length > 1 && args[1] !== null &&
                    typeof args[1].length === 'number' ? args[1].length : null;
                state.iteration_count = args.length > 2 &&
                    typeof args[2] === 'number' ? args[2] : null;
                state.key_length_bits = args.length > 3 &&
                    typeof args[3] === 'number' ? args[3] : null;
                state.call_sequence = ['pbe.key_spec'];
                emitRedactedEvent(
                    'pbe.key_spec.' + index,
                    'crypto',
                    'pbe.key_spec',
                    [state],
                    null,
                    containsCanary(args[0], 0)
                );
                return result;
            };
            emitLifecycle('hook_installed', 'pbe.key_spec.' + index, []);
        });
    } catch (error) {
        emitLifecycle('hook_error', 'pbe.key_spec', [error]);
    }
}

function installRandomHooks(className, hookPrefix, outputMap) {
    try {
        const RandomClass = Java.use(className);
        RandomClass.nextBytes.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                const result = overload.apply(this, args);
                const outputLength = args.length > 0 && args[0] !== null &&
                    typeof args[0].length === 'number' ? args[0].length : null;
                const digest = outputLength !== null &&
                    outputLength <= MAX_RANDOM_FINGERPRINT_BYTES ?
                    byteFingerprint(args[0]) : null;
                const fingerprintStatus = outputLength === null ? 'unavailable' :
                    outputLength > MAX_RANDOM_FINGERPRINT_BYTES ? 'size_limit' :
                        digest === null ? 'unavailable' : 'recorded';
                if (digest !== null) {
                    boundedPut(outputMap, digest, true);
                }
                emitRedactedEvent(
                    hookPrefix + '.next_bytes.' + index,
                    'crypto',
                    'random.next_bytes',
                    [{
                        operation_kind: 'random',
                        random_source: hookPrefix,
                        length: outputLength,
                        output_sha256: digest,
                        fingerprint_status: fingerprintStatus
                    }],
                    null,
                    false
                );
                return result;
            };
            emitLifecycle('hook_installed', hookPrefix + '.next_bytes.' + index, []);
        });
    } catch (error) {
        emitLifecycle('hook_error', hookPrefix + '.next_bytes', [error]);
    }
}

function urlMetadata(value) {
    let text = '';
    try {
        text = String(value);
    } catch (ignored) {
        text = '';
    }
    const schemeMatch = /^([A-Za-z][A-Za-z0-9+.-]*):/.exec(text);
    const scheme = schemeMatch ? schemeMatch[1].toLowerCase() : 'unknown';
    let host = null;
    const hostMatch = /^(?:https?):\/\/([^\/?#]+)/i.exec(text);
    if (hostMatch) {
        host = hostMatch[1].split('@').pop().split(':')[0].toLowerCase();
    }
    return {
        url_scheme: safeId(scheme),
        content_origin: scheme === 'http' || scheme === 'https' ? 'remote' :
            scheme === 'file' ? 'file' : scheme === 'data' ? 'inline' : 'other',
        is_remote: scheme === 'http' || scheme === 'https',
        is_file: scheme === 'file',
        host_sha256: host === null ? null : sha256Text(host),
        length: text.length
    };
}

function webViewId(value) {
    return objectId(value, 'webview');
}

function settingsMetadata(value) {
    const settingsId = objectId(value, 'settings');
    return {
        settings_id: settingsId,
        webview_id: webViewSettings[settingsId] || null
    };
}

function emitWebViewSslCallback(args, hookId) {
    emitRedactedEvent(
        hookId,
        'webview',
        'webview.ssl_error_callback',
        [{
            webview_id: webViewId(args[0]),
            handler_id: objectId(args[1], 'ssl-handler'),
            ssl_error_callback: true
        }],
        null,
        false
    );
}

function instrumentWebViewClient(value) {
    let className = 'unknown';
    try {
        className = String(value.$className || value.getClass().getName());
    } catch (ignored) {
        return;
    }
    if (className === 'android.webkit.WebViewClient') {
        return;
    }
    const instrumentationId = 'webview-client-' + sha256Text(className);
    if (webViewClientInstrumentedClasses[instrumentationId]) {
        return;
    }
    boundedPut(webViewClientInstrumentedClasses, instrumentationId, 'installing');
    try {
        const Implementation = Java.use(className);
        let installed = 0;
        Implementation.onReceivedSslError.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                emitWebViewSslCallback(
                    args,
                    'webview.ssl_error_callback.dynamic.' + index
                );
                return overload.apply(this, args);
            };
            installed += 1;
        });
        if (installed === 0) {
            delete webViewClientInstrumentedClasses[instrumentationId];
            return;
        }
        webViewClientInstrumentedClasses[instrumentationId] = 'installed';
        emitLifecycle('hook_installed', 'webview.ssl_error_callback.dynamic', []);
    } catch (error) {
        delete webViewClientInstrumentedClasses[instrumentationId];
        emitLifecycle('hook_error', 'webview.ssl_error_callback.dynamic', [error]);
    }
}

function installWebSettingsBoolean(methodName, settingName) {
    try {
        const WebSettings = Java.use('android.webkit.WebSettings');
        WebSettings[methodName].overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                const result = overload.apply(this, args);
                const metadata = settingsMetadata(this);
                metadata.setting = settingName;
                metadata.enabled = Boolean(args[0]);
                emitRedactedEvent(
                    'webview.settings.' + safeId(settingName) + '.' + index,
                    'webview',
                    'webview.setting',
                    [metadata],
                    null,
                    false
                );
                return result;
            };
            emitLifecycle(
                'hook_installed',
                'webview.settings.' + safeId(settingName) + '.' + index,
                []
            );
        });
    } catch (error) {
        emitLifecycle('hook_error', 'webview.settings.' + settingName, [error]);
    }
}

function installWebViewHooks() {
    try {
        const WebView = Java.use('android.webkit.WebView');
        WebView.getSettings.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const result = overload.apply(this, arguments);
                const settingsId = objectId(result, 'settings');
                boundedPut(webViewSettings, settingsId, webViewId(this));
                emitRedactedEvent(
                    'webview.get_settings.' + index,
                    'webview',
                    'webview.get_settings',
                    [{ settings_id: settingsId, webview_id: webViewId(this) }],
                    null,
                    false
                );
                return result;
            };
            emitLifecycle('hook_installed', 'webview.get_settings.' + index, []);
        });

        WebView.addJavascriptInterface.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                const result = overload.apply(this, args);
                const name = args.length > 1 ? String(args[1]) : '';
                emitRedactedEvent(
                    'webview.javascript_interface.' + index,
                    'webview',
                    'webview.javascript_interface',
                    [{
                        webview_id: webViewId(this),
                        interface_name_sha256: sha256Text(name),
                        interface_name_length: name.length
                    }],
                    null,
                    containsCanary(name, 0)
                );
                return result;
            };
            emitLifecycle('hook_installed', 'webview.javascript_interface.' + index, []);
        });

        WebView.removeJavascriptInterface.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                const result = overload.apply(this, args);
                const name = args.length > 0 ? String(args[0]) : '';
                emitRedactedEvent(
                    'webview.javascript_interface_removed.' + index,
                    'webview',
                    'webview.javascript_interface_removed',
                    [{
                        webview_id: webViewId(this),
                        interface_name_sha256: sha256Text(name),
                        interface_name_length: name.length
                    }],
                    null,
                    containsCanary(name, 0)
                );
                return result;
            };
            emitLifecycle(
                'hook_installed',
                'webview.javascript_interface_removed.' + index,
                []
            );
        });

        WebView.loadUrl.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                const result = overload.apply(this, args);
                const metadata = urlMetadata(args[0]);
                metadata.webview_id = webViewId(this);
                emitRedactedEvent(
                    'webview.load_url.' + index,
                    'webview',
                    'webview.load_url',
                    [metadata],
                    null,
                    containsCanary(args[0], 0)
                );
                return result;
            };
            emitLifecycle('hook_installed', 'webview.load_url.' + index, []);
        });

        ['loadData', 'loadDataWithBaseURL'].forEach(function (methodName) {
            WebView[methodName].overloads.forEach(function (overload, index) {
                overload.implementation = function () {
                    const args = Array.prototype.slice.call(arguments);
                    const result = overload.apply(this, args);
                    const baseValue = methodName === 'loadDataWithBaseURL' ? args[0] : 'data:';
                    const metadata = urlMetadata(baseValue);
                    metadata.webview_id = webViewId(this);
                    metadata.data_length = args.length > (methodName === 'loadData' ? 0 : 1) &&
                        args[methodName === 'loadData' ? 0 : 1] !== null ?
                        String(args[methodName === 'loadData' ? 0 : 1]).length : 0;
                    emitRedactedEvent(
                        'webview.' + safeId(methodName) + '.' + index,
                        'webview',
                        methodName === 'loadData' ? 'webview.load_data' :
                            'webview.load_data_with_base_url',
                        [metadata],
                        null,
                        args.some(function (item) { return containsCanary(item, 0); })
                    );
                    return result;
                };
                emitLifecycle(
                    'hook_installed',
                    'webview.' + safeId(methodName) + '.' + index,
                    []
                );
            });
        });

        WebView.evaluateJavascript.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                const result = overload.apply(this, args);
                emitRedactedEvent(
                    'webview.evaluate_javascript.' + index,
                    'webview',
                    'webview.evaluate_javascript',
                    [{
                        webview_id: webViewId(this),
                        script_length: args.length > 0 ? String(args[0]).length : 0
                    }],
                    null,
                    containsCanary(args[0], 0)
                );
                return result;
            };
            emitLifecycle('hook_installed', 'webview.evaluate_javascript.' + index, []);
        });

        WebView.setWebContentsDebuggingEnabled.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                const result = overload.apply(this, args);
                emitRedactedEvent(
                    'webview.debugging.' + index,
                    'webview',
                    'webview.debugging',
                    [{ webview_id: 'global', enabled: Boolean(args[0]) }],
                    null,
                    false
                );
                return result;
            };
            emitLifecycle('hook_installed', 'webview.debugging.' + index, []);
        });

        WebView.setWebViewClient.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                if (args.length > 0 && args[0] !== null) {
                    instrumentWebViewClient(args[0]);
                }
                return overload.apply(this, args);
            };
            emitLifecycle('hook_installed', 'webview.client.' + index, []);
        });
    } catch (error) {
        emitLifecycle('hook_error', 'webview.observer', [error]);
    }

    installWebSettingsBoolean('setJavaScriptEnabled', 'javascript_enabled');
    installWebSettingsBoolean('setAllowFileAccess', 'file_access');
    installWebSettingsBoolean('setAllowContentAccess', 'content_access');
    installWebSettingsBoolean('setAllowFileAccessFromFileURLs', 'file_url_access');
    installWebSettingsBoolean(
        'setAllowUniversalAccessFromFileURLs',
        'universal_file_url_access'
    );

    try {
        const WebSettings = Java.use('android.webkit.WebSettings');
        WebSettings.setMixedContentMode.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                const result = overload.apply(this, args);
                const metadata = settingsMetadata(this);
                metadata.setting = 'mixed_content';
                metadata.mixed_content_mode = args[0] === 0 ? 'always_allow' :
                    args[0] === 1 ? 'never_allow' :
                    args[0] === 2 ? 'compatibility' : 'unknown';
                emitRedactedEvent(
                    'webview.settings.mixed_content.' + index,
                    'webview',
                    'webview.setting',
                    [metadata],
                    null,
                    false
                );
                return result;
            };
            emitLifecycle('hook_installed', 'webview.settings.mixed_content.' + index, []);
        });
    } catch (error) {
        emitLifecycle('hook_error', 'webview.settings.mixed_content', [error]);
    }

    try {
        const WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                emitWebViewSslCallback(
                    args,
                    'webview.ssl_error_callback.' + index
                );
                return overload.apply(this, args);
            };
            emitLifecycle('hook_installed', 'webview.ssl_error_callback.' + index, []);
        });
    } catch (error) {
        emitLifecycle('hook_error', 'webview.ssl_error_callback', [error]);
    }

    try {
        const SslErrorHandler = Java.use('android.webkit.SslErrorHandler');
        ['proceed', 'cancel'].forEach(function (methodName) {
            SslErrorHandler[methodName].overloads.forEach(function (overload, index) {
                overload.implementation = function () {
                    const result = overload.apply(this, arguments);
                    emitRedactedEvent(
                        'webview.ssl_error_' + methodName + '.' + index,
                        'webview',
                        'webview.ssl_error_' + methodName,
                        [{
                            handler_id: objectId(this, 'ssl-handler'),
                            decision: methodName
                        }],
                        null,
                        false
                    );
                    return result;
                };
                emitLifecycle(
                    'hook_installed',
                    'webview.ssl_error_' + methodName + '.' + index,
                    []
                );
            });
        });
    } catch (error) {
        emitLifecycle('hook_error', 'webview.ssl_error_handler', [error]);
    }
}

function trustManagerMetadata(value) {
    const hashes = [];
    let custom = false;
    let count = 0;
    if (value !== null && value !== undefined && typeof value.length === 'number') {
        count = Math.min(value.length, 32);
        for (let index = 0; index < count; index += 1) {
            let className = 'unknown';
            try {
                className = String(value[index].$className || value[index].getClass().getName());
            } catch (ignored) {
                className = 'unknown';
            }
            hashes.push(sha256Text(className));
            const lower = className.toLowerCase();
            if (
                className !== 'unknown' &&
                lower.indexOf('com.android.org.conscrypt.') !== 0 &&
                lower.indexOf('org.conscrypt.') !== 0 &&
                lower.indexOf('com.google.android.gms.org.conscrypt.') !== 0 &&
                lower.indexOf('javax.net.ssl.') !== 0 &&
                lower.indexOf('sun.security.ssl.') !== 0 &&
                lower.indexOf('android.net.http.') !== 0 &&
                lower.indexOf('com.android.okhttp.internal.tls.') !== 0 &&
                lower.indexOf('com.squareup.okhttp.internal.tls.') !== 0 &&
                lower.indexOf('okhttp3.internal.tls.') !== 0
            ) {
                custom = true;
                instrumentTrustManager(className);
            }
        }
    }
    return {
        trust_manager_count: count,
        custom_trust_manager: custom,
        manager_class_hashes: hashes
    };
}

function instrumentTrustManager(className) {
    const instrumentationId = 'trust-manager-' + sha256Text(className);
    if (tlsInstrumentedClasses[instrumentationId]) {
        return;
    }
    boundedPut(tlsInstrumentedClasses, instrumentationId, 'installing');
    try {
        const Implementation = Java.use(className);
        let installedOverloads = 0;
        Implementation.checkServerTrusted.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                try {
                    const result = overload.apply(this, args);
                    emitRedactedEvent(
                        'trust.check_server_trusted.' + index,
                        'tls',
                        'tls.check_server_trusted',
                        [{
                            implementation_class_sha256: sha256Text(className),
                            custom_trust_manager: true,
                            decision: 'returned'
                        }],
                        null,
                        false
                    );
                    return result;
                } catch (error) {
                    emitRedactedEvent(
                        'trust.check_server_trusted.' + index,
                        'tls',
                        'tls.check_server_trusted',
                        [{
                            implementation_class_sha256: sha256Text(className),
                            custom_trust_manager: true,
                            decision: 'threw'
                        }],
                        null,
                        false
                    );
                    throw error;
                }
            };
            installedOverloads += 1;
            emitLifecycle('hook_installed', 'trust.check_server_trusted.' + index, []);
        });
        if (installedOverloads === 0) {
            throw new Error('checkServerTrusted has no overloads');
        }
        tlsInstrumentedClasses[instrumentationId] = 'installed';
    } catch (error) {
        delete tlsInstrumentedClasses[instrumentationId];
        emitLifecycle('hook_error', 'trust.check_server_trusted', [error]);
    }
}

function instrumentHostnameVerifier(className) {
    const instrumentationId = 'hostname-verifier-' + sha256Text(className);
    if (tlsInstrumentedClasses[instrumentationId]) {
        return;
    }
    boundedPut(tlsInstrumentedClasses, instrumentationId, 'installing');
    try {
        const Implementation = Java.use(className);
        let installedOverloads = 0;
        Implementation.verify.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                const result = overload.apply(this, args);
                emitRedactedEvent(
                    'trust.hostname_verify.' + index,
                    'tls',
                    'tls.hostname_verify',
                    [{
                        implementation_class_sha256: sha256Text(className),
                        custom_hostname_verifier: true,
                        decision: Boolean(result) ? 'accepted' : 'rejected'
                    }],
                    null,
                    false
                );
                return result;
            };
            installedOverloads += 1;
            emitLifecycle('hook_installed', 'trust.hostname_verify.' + index, []);
        });
        if (installedOverloads === 0) {
            throw new Error('verify has no overloads');
        }
        tlsInstrumentedClasses[instrumentationId] = 'installed';
    } catch (error) {
        delete tlsInstrumentedClasses[instrumentationId];
        emitLifecycle('hook_error', 'trust.hostname_verify', [error]);
    }
}

function hostnameVerifierMetadata(value) {
    let className = 'unknown';
    try {
        className = String(value.$className || value.getClass().getName());
    } catch (ignored) {
        className = 'unknown';
    }
    const lower = className.toLowerCase();
    const custom = !(
        className === 'unknown' ||
        lower.indexOf('javax.net.ssl.') === 0 ||
        lower.indexOf('com.android.org.conscrypt.') === 0 ||
        lower.indexOf('org.conscrypt.') === 0 ||
        lower.indexOf('com.google.android.gms.org.conscrypt.') === 0 ||
        lower.indexOf('android.net.http.') === 0 ||
        lower.indexOf('com.android.okhttp.internal.tls.okhostnameverifier') !== -1 ||
        lower.indexOf('com.squareup.okhttp.internal.tls.okhostnameverifier') !== -1 ||
        lower.indexOf('okhttp3.internal.tls.okhostnameverifier') !== -1
    );
    if (custom) {
        instrumentHostnameVerifier(className);
    }
    return {
        verifier_class_sha256: sha256Text(className),
        custom_hostname_verifier: custom
    };
}

function installTlsHooks() {
    try {
        const SSLContext = Java.use('javax.net.ssl.SSLContext');
        SSLContext.init.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                const result = overload.apply(this, args);
                const metadata = trustManagerMetadata(args.length > 1 ? args[1] : null);
                metadata.ssl_context_id = objectId(this, 'ssl-context');
                emitRedactedEvent(
                    'trust.ssl_context_init.' + index,
                    'tls',
                    'tls.ssl_context_init',
                    [metadata],
                    null,
                    false
                );
                return result;
            };
            emitLifecycle('hook_installed', 'trust.ssl_context_init.' + index, []);
        });
    } catch (error) {
        emitLifecycle('hook_error', 'trust.ssl_context_init', [error]);
    }

    try {
        const TrustManagerFactory = Java.use('javax.net.ssl.TrustManagerFactory');
        TrustManagerFactory.getTrustManagers.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const result = overload.apply(this, arguments);
                emitRedactedEvent(
                    'trust.manager_factory.' + index,
                    'tls',
                    'tls.trust_manager_factory',
                    [trustManagerMetadata(result)],
                    null,
                    false
                );
                return result;
            };
            emitLifecycle('hook_installed', 'trust.manager_factory.' + index, []);
        });
    } catch (error) {
        emitLifecycle('hook_error', 'trust.manager_factory', [error]);
    }

    try {
        const HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        ['setHostnameVerifier', 'setDefaultHostnameVerifier'].forEach(function (methodName) {
            HttpsURLConnection[methodName].overloads.forEach(function (overload, index) {
                overload.implementation = function () {
                    const args = Array.prototype.slice.call(arguments);
                    const result = overload.apply(this, args);
                    emitRedactedEvent(
                        'trust.hostname_verifier.' + safeId(methodName) + '.' + index,
                        'tls',
                        'tls.hostname_verifier_set',
                        [hostnameVerifierMetadata(args[0])],
                        null,
                        false
                    );
                    return result;
                };
                emitLifecycle(
                    'hook_installed',
                    'trust.hostname_verifier.' + safeId(methodName) + '.' + index,
                    []
                );
            });
        });
    } catch (error) {
        emitLifecycle('hook_error', 'trust.hostname_verifier', [error]);
    }

    installMethod(
        'okhttp3.CertificatePinner',
        'check',
        'tls',
        'pinning.certificate_pinner'
    );
}

function storagePathMetadata(value) {
    let path = '';
    try {
        path = typeof value === 'string' ? value : String(value.getAbsolutePath());
    } catch (ignored) {
        path = '';
    }
    const normalized = path.replace(/\\/g, '/');
    const legacyPrefix = '/data/data/' + TARGET_PACKAGE + '/';
    const userRoot = /^\/data\/user\/[0-9]+\//.exec(normalized);
    const userPrefix = userRoot ? userRoot[0] + TARGET_PACKAGE + '/' : null;
    const emulatedRoot = /^\/storage\/emulated\/[0-9]+\//.exec(normalized);
    const emulatedPrefix = emulatedRoot ?
        emulatedRoot[0] + 'Android/data/' + TARGET_PACKAGE + '/' : null;
    const sdcardPrefix = '/sdcard/Android/data/' + TARGET_PACKAGE + '/';
    let area = 'other';
    let packageScoped = false;
    let relative = '';
    if (normalized.indexOf(legacyPrefix) === 0) {
        packageScoped = true;
        relative = normalized.slice(legacyPrefix.length);
        area = relative.indexOf('cache/') === 0 ? 'cache' : 'internal';
    } else if (userPrefix !== null && normalized.indexOf(userPrefix) === 0) {
        packageScoped = true;
        relative = normalized.slice(userPrefix.length);
        area = relative.indexOf('cache/') === 0 ? 'cache' : 'internal';
    } else if (
        emulatedPrefix !== null && normalized.indexOf(emulatedPrefix) === 0
    ) {
        packageScoped = true;
        relative = normalized.slice(emulatedPrefix.length);
        area = relative.indexOf('cache/') === 0 ? 'cache' : 'external_app';
    } else if (normalized.indexOf(sdcardPrefix) === 0) {
        packageScoped = true;
        relative = normalized.slice(sdcardPrefix.length);
        area = relative.indexOf('cache/') === 0 ? 'cache' : 'external_app';
    } else if (
        normalized.indexOf('/storage/emulated/') === 0 ||
        normalized.indexOf('/sdcard/') === 0
    ) {
        area = 'external';
    }
    return {
        path_sha256: path ? sha256Text(normalized) : null,
        storage_area: area,
        package_scoped: packageScoped
    };
}

function installSensitiveSinkHooks() {
    try {
        const Editor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
        Editor.putString.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                const result = overload.apply(this, args);
                const editorId = objectId(this, 'pref-editor');
                const matched = args.some(function (item) { return containsCanary(item, 0); });
                boundedPut(
                    preferenceEditors,
                    editorId,
                    Boolean(preferenceEditors[editorId]) || matched
                );
                emitRedactedEvent(
                    'preferences.put_string.' + index,
                    'storage',
                    'preferences.put_string',
                    [{
                        editor_id: editorId,
                        sink_type: 'shared_preferences',
                        persisted: false
                    }],
                    null,
                    matched
                );
                return result;
            };
            emitLifecycle('hook_installed', 'preferences.put_string.' + index, []);
        });
        ['apply', 'commit'].forEach(function (methodName) {
            Editor[methodName].overloads.forEach(function (overload, index) {
                overload.implementation = function () {
                    const result = overload.apply(this, arguments);
                    const editorId = objectId(this, 'pref-editor');
                    const matched = Boolean(preferenceEditors[editorId]);
                    const persisted = methodName === 'apply' ? true : Boolean(result);
                    emitRedactedEvent(
                        'preferences.' + methodName + '.' + index,
                        'storage',
                        'storage.sink',
                        [{
                            editor_id: editorId,
                            sink_type: 'shared_preferences',
                            persisted: persisted
                        }],
                        null,
                        matched && persisted
                    );
                    delete preferenceEditors[editorId];
                    return result;
                };
                emitLifecycle(
                    'hook_installed',
                    'preferences.' + methodName + '.' + index,
                    []
                );
            });
        });
    } catch (error) {
        emitLifecycle('hook_error', 'preferences.sink', [error]);
    }

    try {
        const ContentValues = Java.use('android.content.ContentValues');
        ContentValues.put.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                const result = overload.apply(this, args);
                const valuesId = objectId(this, 'content-values');
                const matched = args.some(function (item) { return containsCanary(item, 0); });
                boundedPut(
                    contentValues,
                    valuesId,
                    Boolean(contentValues[valuesId]) || matched
                );
                return result;
            };
            emitLifecycle('hook_installed', 'storage.content_values.' + index, []);
        });
    } catch (error) {
        emitLifecycle('hook_error', 'storage.content_values', [error]);
    }

    try {
        const SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
        ['insert', 'insertOrThrow', 'replace', 'update'].forEach(function (methodName) {
            SQLiteDatabase[methodName].overloads.forEach(function (overload, index) {
                overload.implementation = function () {
                    const args = Array.prototype.slice.call(arguments);
                    const result = overload.apply(this, args);
                    let matched = false;
                    let valuesId = null;
                    args.forEach(function (item) {
                        const candidate = objectId(item, 'content-values');
                        if (candidate !== null && contentValues[candidate]) {
                            matched = true;
                            valuesId = candidate;
                        }
                    });
                    let persisted = false;
                    try {
                        const numericResult = Number(result);
                        persisted = methodName === 'update' ?
                            numericResult > 0 : numericResult >= 0;
                    } catch (ignored) {
                        persisted = false;
                    }
                    emitRedactedEvent(
                        'storage.sqlite_' + safeId(methodName) + '.' + index,
                        'storage',
                        'storage.sink',
                        [{
                            content_values_id: valuesId,
                            sink_type: 'sqlite',
                            persisted: persisted
                        }],
                        null,
                        matched
                    );
                    if (valuesId !== null) {
                        delete contentValues[valuesId];
                    }
                    return result;
                };
                emitLifecycle(
                    'hook_installed',
                    'storage.sqlite_' + safeId(methodName) + '.' + index,
                    []
                );
            });
        });
    } catch (error) {
        emitLifecycle('hook_error', 'storage.sqlite_sink', [error]);
    }

    try {
        const FileOutputStream = Java.use('java.io.FileOutputStream');
        FileOutputStream.$init.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                const result = overload.apply(this, args);
                const streamId = objectId(this, 'file-stream');
                boundedPut(fileStreams, streamId, storagePathMetadata(args[0]));
                return result;
            };
            emitLifecycle('hook_installed', 'storage.file_output_init.' + index, []);
        });
        FileOutputStream.write.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                const result = overload.apply(this, args);
                const streamId = objectId(this, 'file-stream');
                const metadata = fileStreams[streamId] || {
                    path_sha256: null,
                    storage_area: 'other',
                    package_scoped: false
                };
                metadata.stream_id = streamId;
                metadata.sink_type = 'file';
                metadata.persisted = true;
                const canaryMatch = args.length >= 3 ?
                    containsCanaryByteRange(args[0], Number(args[1]), Number(args[2])) :
                    args.length === 1 && typeof args[0] !== 'number' ?
                        containsCanary(args[0], 0) : false;
                emitRedactedEvent(
                    'storage.file_write.' + index,
                    'storage',
                    'storage.sink',
                    [metadata],
                    null,
                    canaryMatch
                );
                return result;
            };
            emitLifecycle('hook_installed', 'storage.file_write.' + index, []);
        });
        FileOutputStream.close.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const result = overload.apply(this, arguments);
                delete fileStreams[objectId(this, 'file-stream')];
                return result;
            };
            emitLifecycle('hook_installed', 'storage.file_close.' + index, []);
        });
    } catch (error) {
        emitLifecycle('hook_error', 'storage.file_sink', [error]);
    }

    try {
        const ClipData = Java.use('android.content.ClipData');
        ClipData.newPlainText.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                const result = overload.apply(this, args);
                boundedPut(
                    clipboardValues,
                    objectId(result, 'clip'),
                    args.some(function (item) { return containsCanary(item, 0); })
                );
                return result;
            };
            emitLifecycle('hook_installed', 'storage.clip_data.' + index, []);
        });
        const ClipboardManager = Java.use('android.content.ClipboardManager');
        ClipboardManager.setPrimaryClip.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                const result = overload.apply(this, args);
                const clipId = objectId(args[0], 'clip');
                emitRedactedEvent(
                    'storage.clipboard.' + index,
                    'storage',
                    'storage.sink',
                    [{ clip_id: clipId, sink_type: 'clipboard', persisted: true }],
                    null,
                    Boolean(clipboardValues[clipId])
                );
                delete clipboardValues[clipId];
                return result;
            };
            emitLifecycle('hook_installed', 'storage.clipboard.' + index, []);
        });
    } catch (error) {
        emitLifecycle('hook_error', 'storage.clipboard', [error]);
    }

    try {
        const ContentResolver = Java.use('android.content.ContentResolver');
        ['insert', 'update'].forEach(function (methodName) {
            ContentResolver[methodName].overloads.forEach(function (overload, index) {
                overload.implementation = function () {
                    const args = Array.prototype.slice.call(arguments);
                    const result = overload.apply(this, args);
                    let valuesId = null;
                    let matched = false;
                    args.forEach(function (item) {
                        const candidate = objectId(item, 'content-values');
                        if (candidate !== null && contentValues[candidate]) {
                            valuesId = candidate;
                            matched = true;
                        }
                    });
                    let persisted = result !== null && result !== undefined;
                    if (methodName === 'update') {
                        persisted = Number(result) > 0;
                    }
                    if (matched) {
                        emitRedactedEvent(
                            'sensitive.content_provider_' + methodName + '.' + index,
                            'sensitive_data',
                            'sensitive.sink',
                            [{
                                content_values_id: valuesId,
                                sink_type: 'content_provider',
                                target_scope: 'unknown',
                                boundary_exposed: false,
                                exposure_confidence: 'unknown',
                                persisted: persisted
                            }],
                            null,
                            persisted
                        );
                    }
                    if (valuesId !== null) {
                        delete contentValues[valuesId];
                    }
                    return result;
                };
                emitLifecycle(
                    'hook_installed',
                    'sensitive.content_provider_' + methodName + '.' + index,
                    []
                );
            });
        });
    } catch (error) {
        emitLifecycle('hook_error', 'sensitive.content_provider', [error]);
    }

    try {
        const ContextWrapper = Java.use('android.content.ContextWrapper');
        [
            'sendBroadcast',
            'sendOrderedBroadcast',
            'startActivity',
            'startService',
            'startForegroundService'
        ].forEach(function (methodName) {
            try {
                ContextWrapper[methodName].overloads.forEach(function (overload, index) {
                    overload.implementation = function () {
                        const args = Array.prototype.slice.call(arguments);
                        const result = overload.apply(this, args);
                        const sink = intentSinkMetadata(args[0], methodName);
                        if (sink.matched) {
                            emitRedactedEvent(
                                'sensitive.intent_' + safeId(methodName) + '.' + index,
                                'sensitive_data',
                                'sensitive.sink',
                                [sink.metadata],
                                null,
                                true
                            );
                        }
                        return result;
                    };
                    emitLifecycle(
                        'hook_installed',
                        'sensitive.intent_' + safeId(methodName) + '.' + index,
                        []
                    );
                });
            } catch (error) {
                emitLifecycle(
                    'hook_error',
                    'sensitive.intent_' + safeId(methodName),
                    [error]
                );
            }
        });
    } catch (error) {
        emitLifecycle('hook_error', 'sensitive.intent', [error]);
    }

    try {
        const NotificationManager = Java.use('android.app.NotificationManager');
        NotificationManager.notify.overloads.forEach(function (overload, index) {
            overload.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                const result = overload.apply(this, args);
                const matched = args.some(notificationContainsCanary);
                if (matched) {
                    emitRedactedEvent(
                        'sensitive.notification.' + index,
                        'sensitive_data',
                        'sensitive.sink',
                        [{
                            sink_type: 'notification',
                            target_scope: 'system_ui',
                            boundary_exposed: true,
                            exposure_confidence: 'clear',
                            persisted: false
                        }],
                        null,
                        true
                    );
                }
                return result;
            };
            emitLifecycle('hook_installed', 'sensitive.notification.' + index, []);
        });
    } catch (error) {
        emitLifecycle('hook_error', 'sensitive.notification', [error]);
    }
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
            ['android.database.sqlite.SQLiteDatabase', 'rawQuery', 'storage', 'sqlite.raw_query'],
            ['android.database.sqlite.SQLiteDatabase', 'query', 'storage', 'sqlite.query'],
            ['android.database.sqlite.SQLiteDatabase', 'execSQL', 'storage', 'sqlite.exec_sql'],
            ['java.io.FileInputStream', '$init', 'storage', 'file.read'],
            ['android.util.Log', 'd', 'logging', 'log.debug'],
            ['android.util.Log', 'i', 'logging', 'log.info'],
            ['android.util.Log', 'w', 'logging', 'log.warn'],
            ['android.util.Log', 'e', 'logging', 'log.error'],
            ['okhttp3.OkHttpClient', 'newCall', 'network', 'okhttp.new_call']
        ];

        hooks.forEach(function (definition) {
            installMethod(definition[0], definition[1], definition[2], definition[3]);
        });
        installCryptoHooks();
        installDigestHooks();
        installMacHooks();
        installPbeHooks();
        installRandomHooks('java.security.SecureRandom', 'secure_random', secureRandomOutputs);
        installRandomHooks('java.util.Random', 'weak_random', weakRandomOutputs);
        installWebViewHooks();
        installTlsHooks();
        installSensitiveSinkHooks();
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
