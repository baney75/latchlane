"""Disposable real-browser flow. Never uses a user's vault or clipboard."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

import httpx
from playwright.sync_api import sync_playwright

ROOT=Path(__file__).parents[1]
PORT=19473
ORIGIN=f'http://127.0.0.1:{PORT}'
PASSPHRASE='browser-fixture-passphrase'


def wait_for_server():
    for _ in range(100):
        try:
            if httpx.get(ORIGIN+'/api/status',trust_env=False).status_code==200:return
        except httpx.HTTPError: pass
        time.sleep(.1)
    raise RuntimeError('Fixture server did not start.')


def main():
    with tempfile.TemporaryDirectory(prefix='latchlane-browser-') as tmp:
        env=os.environ.copy();env['LATCHLANE_HOME']=tmp
        python=str(ROOT/'.venv'/('Scripts/python.exe' if os.name=='nt' else 'bin/python'))
        process=subprocess.Popen([python,'-c','from latchlane.cli import main; main()','start','--port',str(PORT),'--no-open'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            wait_for_server()
            # The fixture's one-use owner ticket is read only and is never logged.
            ticket=json.loads((Path(tmp)/'owner-ticket.local.json').read_text())['url']
            assert ticket.startswith(ORIGIN+'/#')
            with sync_playwright() as p:
                browser=p.chromium.launch()
                context=browser.new_context(viewport={'width':1440,'height':1050})
                context.add_init_script("""
                    (() => {
                      const reads=['manual-save-unrelated','watch-before','fixture-watch-secret','newer-fixture-value'];
                      let index=0; const writes=[];
                      Object.defineProperty(navigator, 'clipboard', {configurable:true, value:{
                        readText: async () => reads[Math.min(index++, reads.length-1)],
                        writeText: async value => { writes.push(value); }
                      }});
                      window.__fixtureClipboard={writes, value:() => reads[Math.min(index, reads.length-1)]};
                    })();
                """)
                page=context.new_page();errors=[]
                page.on('pageerror',lambda error:errors.append(str(error)))
                page.on('dialog',lambda dialog:dialog.accept())

                # A normal URL and an invalid setup fragment cannot initialize a vault.
                page.goto(ORIGIN);page.locator('#enter').wait_for(state='visible');assert page.locator('#enter').is_disabled()
                # Install help stays usable before unlocking. A native install event takes
                # priority; otherwise it shows browser-specific, non-secret guidance.
                page.evaluate('''() => { const event = new Event('beforeinstallprompt'); Object.defineProperty(event, 'prompt', {value: () => { window.__fixtureInstallPrompted = true; }}); Object.defineProperty(event, 'userChoice', {value: Promise.resolve({outcome: 'accepted'})}); window.dispatchEvent(event); }''')
                page.locator('#welcome-install-help').click();assert page.evaluate('window.__fixtureInstallPrompted === true')
                page.locator('#install-help').click();page.locator('#app-dialog').wait_for(state='visible');assert 'Install Latchlane in your browser.' in page.locator('#app-dialog').inner_text();assert 'latchlane install-app' in page.locator('#agent-setup-prompt').inner_text();assert 'pairing code' in page.locator('#app-dialog').inner_text();assert page.evaluate('document.documentElement.scrollWidth <= innerWidth');page.screenshot(path=str(ROOT/'docs/install-help-desktop.png'),full_page=False,animations='disabled');page.locator('#app-dialog [data-close]').first.click()
                page.set_viewport_size({'width':390,'height':844});page.locator('#install-help').click();page.locator('#app-dialog').wait_for(state='visible');assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'),'install guide overflow at 390';page.screenshot(path=str(ROOT/'docs/install-help-mobile.png'),full_page=False,animations='disabled');page.locator('#app-dialog [data-close]').first.click();page.set_viewport_size({'width':1440,'height':1050})
                page.goto(ticket.replace('/#','/?fixture-setup=1#'));page.locator('#password').fill(PASSPHRASE);page.locator('#confirm').fill('different-fixture-passphrase');page.locator('#enter').click()
                page.locator('#notice.error').wait_for(state='visible')
                # The valid one-use setup window recovers from a mismatched passphrase without a new ticket.
                page.locator('#confirm').fill(PASSPHRASE);page.locator('[name="session-mode"][value="remember"]').check();page.locator('#enter').click();page.locator('#dashboard').wait_for(state='visible')
                assert any(cookie['name']=='latchlane_owner' and cookie['expires']-time.time()>25*24*3600 for cookie in context.cookies())
                assert page.locator('[data-mode="ask"]').get_attribute('aria-pressed')=='true'

                # A browser-side connection failure exposes a retry that restores this session.
                page.route('**/api/owner',lambda route:route.abort());page.reload();page.locator('#retry').wait_for(state='visible')
                page.unroute('**/api/owner');page.locator('#retry').click();page.locator('#dashboard').wait_for(state='visible')
                manifest=httpx.get(ORIGIN+'/manifest.webmanifest',trust_env=False).json();assert manifest['display']=='standalone'
                worker=httpx.get(ORIGIN+'/sw.js',trust_env=False).text;assert '/api/' not in worker and 'cache.addAll([OFFLINE_PAGE, "/assets/offline.css"])' in worker
                assert page.evaluate('async () => { const registration = await navigator.serviceWorker.ready; return registration.active.scriptURL.endsWith("/sw.js"); }')
                assert page.evaluate('document.documentElement.dataset.displayMode') in ('browser','standalone')
                page.locator('#app-help').click();assert page.locator('#app-dialog').is_visible();page.locator('#app-dialog [data-close]').first.click()
                assert page.locator('#notifications').is_visible()
                context.set_offline(True);page.goto(ORIGIN,wait_until='domcontentloaded');page.get_by_role('heading',name='Your vault host is offline.').wait_for()
                assert page.locator('style').count()==0 and page.locator('a.retry').get_attribute('href')=='/'
                assert page.locator('.card').evaluate('el => getComputedStyle(el).backgroundColor')=='rgb(255, 254, 248)'
                cached=page.evaluate('async () => { const names = await caches.keys(); const entries = await Promise.all(names.map(async name => (await caches.open(name)).keys())); return entries.flat().map(request => new URL(request.url).pathname).sort(); }')
                assert cached==['/assets/offline.css','/offline.html'],cached
                context.set_offline(False);page.locator('a.retry').click();page.locator('#dashboard').wait_for(state='visible')

                page.locator('#add').click()
                page.locator('#key-name').fill('invalid-origin');page.locator('#key-origin').fill('http://api.example.com');page.locator('#key-value').fill('disposable-invalid-fixture');page.locator('#key-form [type=submit]').click()
                alert=page.locator('#key-dialog .dialog-notice.error');alert.wait_for(state='visible');assert alert.get_attribute('role')=='alert'
                assert alert.evaluate('(el) => { const r=el.getBoundingClientRect(); return el.contains(document.elementFromPoint(r.x+r.width/2,r.y+r.height/2)); }')
                page.locator('[data-close="key-dialog"]').click();page.locator('#add').click()
                page.locator('#key-name').fill('studio-ai');page.locator('#key-origin').fill('https://api.example.com')
                page.locator('#key-header').select_option('X-API-Key');assert page.locator('#key-prefix').input_value()==''
                page.locator('#key-header').select_option('Authorization');assert page.locator('#key-prefix').input_value()=='Bearer '
                page.locator('#key-prefix').select_option('Basic ');assert page.locator('#key-prefix').input_value()=='Basic '
                page.locator('#key-prefix').select_option('Bearer ');page.locator('#key-value').fill('dummy-browser-key-not-real');page.locator('#key-form summary').click();page.locator('#safe-paths').fill('/v1/models');page.locator('#key-form [type=submit]').click();page.locator('#key-dialog').wait_for(state='hidden')
                page.locator('#keys strong').get_by_text('studio-ai',exact=True).wait_for();assert 'dummy-browser-key-not-real' not in page.locator('body').inner_text()

                # The clipboard is a fixture-only browser stub. A newer copy must not be cleared.
                page.locator('#add').click();page.locator('#key-name').fill('watch-copy-key');page.locator('#key-origin').fill('https://watch.example.com');page.locator('#watch-copy').click();page.locator('#key-dialog').wait_for(state='hidden',timeout=5000)
                page.locator('#keys strong').get_by_text('watch-copy-key',exact=True).wait_for();assert page.evaluate('window.__fixtureClipboard.writes.length')==0
                assert 'fixture-watch-secret' not in page.locator('body').inner_text()
                page.goto(ORIGIN+'/?window=capture&capture=captured-key&origin=https%3A%2F%2Fcapture.example.com');page.locator('#key-dialog').wait_for(state='visible')
                assert page.locator('#welcome-intro').is_hidden() and page.locator('#capture-advanced').count()==1
                page.set_viewport_size({'width':390,'height':844});page.screenshot(path=str(ROOT/'docs/mobile.png'),full_page=False,animations='disabled');assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'),'capture overflow at 390'
                page.evaluate('''() => { window.__fixtureManualClipboardReads=0; window.__fixtureReadText=navigator.clipboard.readText; navigator.clipboard.readText=() => { window.__fixtureManualClipboardReads += 1; return new Promise(() => {}); }; }''')
                page.locator('#key-value').fill('capture-browser-key-not-real');page.locator('#save-key').click();page.locator('#capture-success').wait_for(state='visible',timeout=2000);assert page.evaluate('window.__fixtureManualClipboardReads')==0;assert 'capture-browser-key-not-real' not in page.locator('body').inner_text();page.evaluate('navigator.clipboard.readText=window.__fixtureReadText')
                page.evaluate('''() => { let reads=0; window.__fixtureExplicitClipboardReads=0; navigator.clipboard.readText=() => { reads += 1; window.__fixtureExplicitClipboardReads=reads; if(reads===1)return Promise.resolve('explicit-before'); if(reads===2)return Promise.resolve('explicit-hang-key'); return new Promise(() => {}); }; }''')
                page.locator('#capture-another').click();page.locator('#key-name').fill('explicit-watch-key');page.locator('#key-origin').fill('https://explicit.example.com');page.locator('#watch-copy').click();page.locator('#capture-success').wait_for(state='visible',timeout=2000);assert page.evaluate('window.__fixtureExplicitClipboardReads')==3;page.wait_for_timeout(2100);assert 'explicit-hang-key' not in page.locator('body').inner_text();page.locator('#capture-done').click();page.locator('#capture-success').wait_for(state='visible');page.locator('[data-close="key-dialog"]').click();page.set_viewport_size({'width':1440,'height':1050})
                studio=page.locator('.key-row').filter(has_text='studio-ai');studio.get_by_role('button',name='Edit studio-ai').click();assert not page.locator('#key-value').evaluate('el => el.required');page.locator('#key-origin').fill('https://edited.example.com');page.locator('#save-key').click();page.locator('#key-dialog').wait_for(state='hidden');page.get_by_text('https://edited.example.com',exact=True).wait_for()

                page.locator('[data-mode="auto"]').click();page.locator('#confirm-mode').click();page.locator('[data-mode="auto"][aria-pressed="true"]').wait_for()
                page.locator('#pair').click();page.locator('#pair-result').wait_for(state='visible')
                assert page.locator('#pair-command').inner_text()==f"latchlane pair {ORIGIN} --name 'My agent'"
                code=page.locator('#pair-code').inner_text();assert len(code)>20
                with httpx.Client(base_url=ORIGIN,headers={'X-Latchlane':'1'},trust_env=False) as agent:
                    token=agent.post('/api/pair',json={'code':code,'name':'Design agent'}).json()['token'];agent.headers['Authorization']='Bearer '+token
                    denied=agent.post('/api/requests',json={'key':'studio-ai','kind':'lease','purpose':'Check a local design preview'}).json()['id']
                    page.get_by_text('Deny',exact=True).click(timeout=10000);page.locator('#approvals').wait_for(state='hidden');assert agent.post('/api/requests/'+denied+'/consume').status_code==403
                    approved=agent.post('/api/requests',json={'key':'studio-ai','kind':'lease','purpose':'Run the local design preview'}).json()['id']
                    page.get_by_text('Approve once',exact=True).click(timeout=10000);page.locator('#approvals').wait_for(state='hidden');assert agent.post('/api/requests/'+approved+'/consume').json()['value']=='dummy-browser-key-not-real'
                    page.get_by_role('button',name='Revoke Design agent').click();assert agent.get('/api/keys').status_code==401

                page.locator('#pair').click();page.locator('#pair-result').wait_for(state='visible');code=page.locator('#pair-code').inner_text()
                with httpx.Client(base_url=ORIGIN,headers={'X-Latchlane':'1'},trust_env=False) as agent:
                    agent.post('/api/pair',json={'code':code,'name':'Persistent agent'}).raise_for_status()
                # Server revision update clears the pairing secret before captures and preserves focus on unchanged refreshes.
                page.locator('#pair').focus();page.locator('#pair-result').wait_for(state='hidden',timeout=10000);assert page.evaluate('document.activeElement.id')=='pair'
                assert not page.locator('#pair-code').inner_text();assert 'fixture-watch-secret' not in page.locator('body').inner_text()
                page.screenshot(path=str(ROOT/'docs/console.png'),full_page=True,animations='disabled')
                page.locator('#mcp-guide').click();assert page.locator('#mcp-dialog').is_visible();assert '"args": ["mcp"]' in page.locator('#mcp-dialog').inner_text();page.locator('#mcp-dialog [data-close]').first.click()
                page.locator('#sync-guide').click();assert page.locator('#sync-dialog').is_visible();page.locator('#sync-dialog [data-close]').first.click()
                for width in (320,390,768,1280):
                    page.set_viewport_size({'width':width,'height':1000});page.wait_for_timeout(100);assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'),f'overflow at {width}';page.evaluate('window.scrollTo(0,0)') if width==320 else None;page.screenshot(path=str(ROOT/'docs/console-320.png'),full_page=False,animations='disabled') if width==320 else None
                page.set_viewport_size({'width':320,'height':1000});page.locator('#mcp-guide').click();assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'),'modal overflow at 320';page.locator('#mcp-dialog [data-close]').first.click()
                page.locator('#lock').click();page.locator('#welcome').wait_for(state='visible');assert page.locator('#key-dialog').is_hidden()
                page.locator('#password').fill(PASSPHRASE);page.locator('#enter').click();page.locator('#dashboard').wait_for(state='visible')
                page.locator('#keys strong').get_by_text('studio-ai',exact=True).wait_for();page.locator('#clients').get_by_text('Persistent agent',exact=True).wait_for()
                if page.locator('#key-dialog').is_visible():page.locator('[data-close="key-dialog"]').click()
                page.locator('#logout').click();page.locator('#welcome').wait_for(state='visible');page.locator('#password').fill(PASSPHRASE);page.locator('#enter').click();page.locator('#dashboard').wait_for(state='visible')
                assert not errors,errors
                browser.close()
                print('PASS: empty-profile setup/mismatch recovery, pairing, auth prefixes, approvals, revocation, fixture-only clipboard, lock/unlock, and 320/390/768/1280 layouts. No user clipboard or vault accessed.')
        finally:
            process.terminate();process.wait(timeout=10)

if __name__=='__main__':main()
