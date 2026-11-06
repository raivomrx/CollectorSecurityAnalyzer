// Isolated Chromium profile. Inject only a fake clipboard sink; never touch the user's clipboard.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

let input = '';
for await (const chunk of process.stdin) input += chunk;
const { url, browserPath, profile, pin } = JSON.parse(input);
assert.equal(new URL(url).hostname, '127.0.0.1');
const browser = spawn(browserPath, ['--headless=new', '--no-first-run', '--no-default-browser-check',
    '--disable-background-networking', '--remote-debugging-port=0',
    '--ignore-certificate-errors-spki-list=' + pin, '--user-data-dir=' + profile, 'about:blank'],
    { windowsHide: true, stdio: 'ignore' });
let ws;
try {
    let port;
    for (let i = 0; i < 100 && !port; i++) {
        try { [port] = (await readFile(join(profile, 'DevToolsActivePort'), 'utf8')).split(/\r?\n/); }
        catch { await delay(100); }
    }
    assert.match(port, /^\d+$/);
    const targets = await (await fetch('http://127.0.0.1:' + port + '/json/list')).json();
    ws = new WebSocket(targets.find(target => target.type === 'page').webSocketDebuggerUrl);
    const pending = new Map();
    ws.addEventListener('message', event => {
        const response = JSON.parse(event.data);
        if (response.id && pending.has(response.id)) {
            const resolve = pending.get(response.id);
            pending.delete(response.id);
            resolve(response);
        }
    });
    await new Promise((resolve, reject) => {
        ws.addEventListener('open', resolve, { once: true });
        ws.addEventListener('error', reject, { once: true });
    });
    let id = 0;
    async function call(method, params = {}) {
        const key = ++id;
        const result = await Promise.race([new Promise(resolve => {
            pending.set(key, resolve);
            ws.send(JSON.stringify({ id: key, method, params }));
        }), delay(8000, null, { ref: false })]);
        assert.ok(result && !result.error, 'Browser command failed: ' + method);
        return result.result;
    }
    async function evaluate(expression) {
        const result = await call('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true, userGesture: true });
        assert.ok(!result.exceptionDetails, 'Browser DOM evaluation failed');
        return result.result.value;
    }
    await call('Page.enable');
    const navigation = await call('Page.navigate', { url });
    assert.ok(!navigation.errorText, 'Join page did not load');
    let ready = false;
    for (let i = 0; i < 50 && !ready; i++) {
        ready = await evaluate("!!document.querySelector('button[data-copy-command]')");
        if (!ready) await delay(100);
    }
    assert.ok(ready);
    const commands = await evaluate(`(async () => {
        const copied = [];
        Object.defineProperty(navigator, "clipboard", { value: {writeText: async text => copied.push(text)}, configurable: true });
        const buttons = Array.from(document.querySelectorAll("button[data-copy-command]"));
        for (const button of buttons) button.click();
        await Promise.resolve();
        const labels = buttons.map(button => button.textContent);
        Object.defineProperty(navigator, "clipboard", {value: {writeText: async () => {throw Error("denied");}}});
        buttons[1].click();
        await Promise.resolve();
        return { copied, labels, selected: window.getSelection().toString() };
    })()`);
    assert.equal(commands.copied.length, 4);
    assert.deepEqual(commands.labels, ['Copied', 'Copied', 'Copied', 'Copied']);
    assert.doesNotMatch(commands.copied[0], /ExecutionPolicy|--quick-run/);
    assert.match(commands.copied[1], /-ExecutionPolicy Bypass .* --quick-run"/);
    assert.equal(commands.selected, commands.copied[1]);
    await call('Browser.close').catch(() => {});
    console.log('Join browser Copy and clipboard-denied fallback: PASS');
} finally {
    if (ws) ws.close();
    if (browser.exitCode === null) {
        browser.kill();
        await Promise.race([new Promise(resolve => browser.once('exit', resolve)), delay(3000)]);
    }
}
